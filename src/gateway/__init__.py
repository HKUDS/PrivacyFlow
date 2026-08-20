"""PrivacyFlow local privacy gateway."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("privacyflow")
except PackageNotFoundError:
    try:
        __version__ = version("agent-privacy-gateway")
    except PackageNotFoundError:
        __version__ = "0.1.0"
