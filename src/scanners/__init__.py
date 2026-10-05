"""Scanner registry — auto-discovers scanners in this package."""
import importlib
import logging
import pkgutil

from src.scanners._base import Scanner

logger = logging.getLogger(__name__)


def _discover_scanners() -> list:
    """Auto-discover Scanner implementations in src.scanners package."""
    scanners = []
    package = importlib.import_module("src.scanners")
    for _importer, modname, _ispkg in pkgutil.iter_modules(package.__path__):
        if modname.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"src.scanners.{modname}")
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    isinstance(obj, type)
                    and obj.__module__ == mod.__name__
                    and hasattr(obj, "name")
                    and hasattr(obj, "scan")
                    and hasattr(obj, "collect_daily_data")
                ):
                    try:
                        instance = obj()
                        if isinstance(instance, Scanner):
                            scanners.append(instance)
                            logger.debug("Discovered scanner: %s from %s", instance.name, modname)
                    except Exception:
                        logger.warning("Failed to instantiate scanner %s from %s", obj.__name__, modname, exc_info=True)
        except Exception:
            logger.exception("Failed to load scanner module: %s", modname)
    return scanners


ALL_SCANNERS = _discover_scanners()


def get_enabled_scanners() -> list:
    return [s for s in ALL_SCANNERS if s.enabled]
