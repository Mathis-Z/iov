import pytest

from evaluate_iov.host import base
from evaluate_iov.host.pkgdb import InstalledPackage


@pytest.fixture(autouse=True)
def fresh_host_caches():
    """Host facts are cached per pass; never let one test see another's."""
    base.reset_caches()
    yield
    base.reset_caches()


def pkg(name, version, arch="amd64", manager="dpkg", signature=""):
    return InstalledPackage(name, version, arch, name, manager, signature)
