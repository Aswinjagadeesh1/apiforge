"""Out-of-band (OOB) interaction listener for blind-SSRF detection.

Blind SSRF returns nothing useful in the HTTP response — the server makes the
request silently. The only way to confirm it is to inject a URL pointing at a
server WE control and watch whether the target's backend actually connects to
it. This module is that server.

SCOPE / HONEST LIMITATION:
  This listener binds to a local interface. It can therefore only catch blind
  SSRF when the TARGET can reach this machine — i.e. the target runs on the same
  host or the same network (localhost, Docker, a lab, an internal API). It does
  NOT work against a remote internet target that cannot route back to your
  laptop; that requires a public collaborator server, which conflicts with
  APIForge's local-first design and is out of scope by choice.

Each probe embeds a unique token in its path (/oob/<token>). When the target
fetches it, we record the token as "hit", which ties the interaction back to the
specific endpoint+parameter that triggered it.
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _OOBHandler(BaseHTTPRequestHandler):
    # Set by the server instance.
    hits: set = set()

    def _record(self):
        # Path looks like /oob/<token> (may have query/junk appended).
        parts = self.path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "oob":
            token = parts[1].split("?")[0]
            type(self).hits.add(token)

    def do_GET(self):
        self._record()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"apiforge-oob-ok")

    def do_POST(self):
        self._record()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"apiforge-oob-ok")

    def log_message(self, *args):  # silence
        pass


class OOBListener:
    """Local HTTP catcher for blind-SSRF callbacks.

    Usage:
        oob = OOBListener()          # binds an ephemeral local port
        oob.start()
        url = oob.probe_url()        # unique http://<host>:<port>/oob/<token>
        ... inject url into the target parameter, send request ...
        if oob.was_hit(token):       # target's backend called us -> blind SSRF
            ...
        oob.stop()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 advertise_host: str | None = None) -> None:
        self.host = host
        # advertise_host is what we put INTO the injected URL. When the target
        # runs in Docker (e.g. crAPI), 127.0.0.1 refers to the container, not us,
        # so callers can advertise the host-gateway address instead.
        self.advertise_host = advertise_host or host
        self._server = ThreadingHTTPServer((host, port), _OOBHandler)
        self.port = self._server.server_address[1]
        self._thread: threading.Thread | None = None
        # per-instance hit set
        self._hits: set = set()
        _OOBHandler.hits = self._hits
        self._counter = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def new_token(self) -> str:
        self._counter += 1
        return f"af{self._counter:04d}{self._server.server_address[1]}"

    def probe_url(self, token: str) -> str:
        return f"http://{self.advertise_host}:{self.port}/oob/{token}"

    def was_hit(self, token: str) -> bool:
        return token in self._hits

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    @staticmethod
    def docker_host_gateway() -> str | None:
        """Best-effort host address reachable from inside a Docker container.
        host.docker.internal works on Docker Desktop; on Linux the default
        bridge gateway is usually 172.17.0.1."""
        for cand in ("host.docker.internal", "172.17.0.1"):
            try:
                socket.gethostbyname(cand)
                return cand
            except Exception:
                continue
        return None
