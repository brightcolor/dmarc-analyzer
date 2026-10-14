"""Packages with security fixes stay at or above the first version that contains the fix."""
from importlib.metadata import version
from pathlib import Path

import pytest
from packaging.version import Version

REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"

# Package → first version with the fixes of the security advisories that concern this application
MINIMUM_VERSIONS = {
    "starlette": "1.3.1",
    "python-multipart": "0.0.31",
    "python-dotenv": "1.2.2",
}


def _pinned() -> dict[str, str]:
    pins = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        requirement = line.split("#", 1)[0].strip()
        if "==" in requirement:
            name, pinned = requirement.split("==", 1)
            pins[name.split("[", 1)[0].strip().lower()] = pinned.strip()
    return pins


@pytest.mark.parametrize(("package", "minimum"), MINIMUM_VERSIONS.items())
def test_requirements_pin_a_fixed_version(package, minimum):
    assert Version(_pinned()[package]) >= Version(minimum)


@pytest.mark.parametrize(("package", "minimum"), MINIMUM_VERSIONS.items())
def test_installed_version_contains_the_fix(package, minimum):
    assert Version(version(package)) >= Version(minimum)
