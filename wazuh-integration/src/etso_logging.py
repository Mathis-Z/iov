import logging
import logging.config
from pathlib import Path

from config import LOG_FILE, LOG_LEVEL


def configure_logging():
    """Log ETSO's own loggers ("etso.*") to the console and to two files next
    to LOG_FILE: "<name>-debug.log" with everything, "<name>-info.log" from INFO."""
    handlers = {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["etso_only"],
            "formatter": "default",
        }
    }

    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    handlers["debug_file"] = {
        "class": "logging.FileHandler",
        "filters": ["etso_only"],
        "formatter": "default",
        "filename": str(LOG_FILE.removesuffix(".log") + "-debug.log"),
        "encoding": "utf-8"
    }

    handlers["info_file"] = {
        "class": "logging.FileHandler",
        "level": "INFO",
        "filters": ["etso_only"],
        "formatter": "default",
        "filename": str(LOG_FILE.removesuffix(".log") + "-info.log"),
        "encoding": "utf-8"
    }

    root_handlers = ["console", "debug_file", "info_file"]

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "etso_only": {
                "()": lambda: logging.Filter("etso")
            }
        },
        "handlers": handlers,
        "formatters": {
            "default": {
                "format": "[%(asctime)s][%(name)s][%(levelname)s] %(message)s"
            }
        },
        "root": {
            "level": LOG_LEVEL,
            "handlers": root_handlers
        }
    })
