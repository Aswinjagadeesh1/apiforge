"""Security checks package.

Import ALL_CHECKS to get the list of instantiated checks the scanner runs.
"""
from apiforge.checks.bfla import BFLACheck
from apiforge.checks.bola_numeric import BolaNumericCheck
from apiforge.checks.data_exposure import SensitiveDataExposureCheck
from apiforge.checks.mass_assignment import MassAssignmentCheck
from apiforge.checks.jwt_alg_none import JWTAlgNoneCheck
from apiforge.checks.jwt_weak_secret import JWTWeakSecretCheck

ALL_CHECKS = [
    BolaNumericCheck(),
    BFLACheck(),
    MassAssignmentCheck(),
    SensitiveDataExposureCheck(),
    JWTAlgNoneCheck(),
    JWTWeakSecretCheck(),
]
