"""Logging configuration shared by the CLI and the daemon."""

import logging
import os
import sys

# Every module in the package logs under this one name, so both entrypoints
# configure logging by touching a single logger.
LOGGER_NAME = "evaluate-iov"

LOG_FORMAT = "%(asctime)s %(name)s [%(levelname)s] %(funcName)s:%(lineno)d: %(message)s"


def configure_logging(level_name: str | None = None, *, default: str = "INFO") -> logging.Logger:
    """Set up the package logger.

    Everything goes to stderr, which keeps stdout free for the standalone CLI's
    own output and lands in the journal under systemd.

    The level comes from level_name, falling back to EVALUATE_IOV_LOG_LEVEL and
    then to the given default.
    """
    requested = (level_name or os.environ.get("EVALUATE_IOV_LOG_LEVEL", default)).strip().upper()
    level = getattr(logging, requested, None)
    if not isinstance(level, int):
        level = logging.INFO

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)

    if not isinstance(getattr(logging, requested, None), int):
        logger.warning("Unrecognized log level %r, falling back to INFO", requested)
    return logger
