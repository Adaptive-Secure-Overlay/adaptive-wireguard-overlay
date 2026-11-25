"""Exact qualified interpreter/library contract, checked before socket binding."""
import sys
import cryptography

PYTHON_VERSION = (3, 14, 8)
CRYPTOGRAPHY_VERSION = '50.0.2'


def check_versions(python_version, cryptography_version):
    if tuple(python_version) != PYTHON_VERSION or cryptography_version != CRYPTOGRAPHY_VERSION:
        raise RuntimeError('MCC requires Python 3.14.8 and cryptography 50.0.2; '
                           'use the isolated project runtime, not system Python')


def require_runtime():
    check_versions(sys.version_info[:3], cryptography.__version__)
