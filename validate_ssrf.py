"""End-to-end SSRF check validation: in-band (should flag), blind (should flag
via OOB), safe (must NOT flag)."""
import asyncio, threading, time
from samples import ssrf_test_server
from http.server import ThreadingHTTPServer
from apiforge.executor.http_executor import HttpExecutor
from apiforge.executor.oob_listener import OOBListener
from apiforge.checks.ssrf import SSRFCheck
from apiforge.models import Endpoint

# start the vulnerable test app
srv = ThreadingHTTPServer(("127.0.0.1", 8901), ssrf_test_server.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)

async def main():
    ex = HttpExecutor(base_url="http://127.0.0.1:8901", auth_header="Authorization")
    oob = OOBListener(host="127.0.0.1")   # target is localhost, so 127.0.0.1 is reachable
    oob.start()
    ex.oob = oob
    ex.oob_wait = 1.5
    check = SSRFCheck()

    cases = {
        "inband (want FLAG)": Endpoint(name="inband", method="POST",
            raw_url="http://127.0.0.1:8901/api/fetch/inband", path="/api/fetch/inband",
            query={}, headers={}, body={"target_url": "http://example.com/"}),
        "blind  (want FLAG)": Endpoint(name="blind", method="POST",
            raw_url="http://127.0.0.1:8901/api/fetch/blind", path="/api/fetch/blind",
            query={}, headers={}, body={"target_url": "http://example.com/"}),
        "safe   (want NONE)": Endpoint(name="safe", method="POST",
            raw_url="http://127.0.0.1:8901/api/fetch/safe", path="/api/fetch/safe",
            query={}, headers={}, body={"target_url": "http://example.com/"}),
    }
    for label, ep in cases.items():
        applicable = check.is_applicable(ep)
        finding = await check.run(ep, {}, ex) if applicable else None
        verdict = "FLAGGED" if finding else "no finding"
        print(f"  {label}: applicable={applicable}  -> {verdict}")
        if finding:
            kind = "blind" if "blind" in finding.description else "in-band"
            print(f"      [{kind}] {finding.description[:90]}...")
    oob.stop()
    await ex.close()

asyncio.run(main())
