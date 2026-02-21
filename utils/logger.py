"""
NetProbe — Logging configuration.

Provides a colour-coded console handler (optionally with a file handler)
and a single ``setup_logger`` function consumed by every module.
"""

import logging
import sys
from typing import Optional


# ──────────────────────────────────────────────
# Colour mapping for log levels
# ──────────────────────────────────────────────
LEVEL_COLOURS = {
    logging.DEBUG:    "\033[96m",   # cyan
    logging.INFO:     "\033[92m",   # green
    logging.WARNING:  "\033[93m",   # yellow
    logging.ERROR:    "\033[91m",   # red
    logging.CRITICAL: "\033[1;91m", # bold red
}
RESET = "\033[0m"


class ColouredFormatter(logging.Formatter):
    """Inject ANSI colours into log-level names."""

    def __init__(self, fmt: str, datefmt: Optional[str] = None, use_colour: bool = True) -> None:
        super().__init__(fmt, datefmt)
        self.use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colour:
            colour = LEVEL_COLOURS.get(record.levelno, "")
            record.levelname = f"{colour}{record.levelname}{RESET}"
        return super().format(record)


def setup_logger(
    verbose: bool = False,
    log_file: Optional[str] = None,
    use_colour: bool = True,
) -> logging.Logger:
    """Create and return the application-wide logger.

    Parameters
    ----------
    verbose : bool
        If *True* the console level is set to ``DEBUG``; otherwise ``INFO``.
    log_file : str | None
        Optional path to a log file.  When given a ``FileHandler`` is added
        with ``DEBUG`` level regardless of *verbose*.
    use_colour : bool
        Disable ANSI colours (e.g. when piping to a file).

    Returns
    -------
    logging.Logger
        Configured ``netprobe`` root logger.
    """
    logger = logging.getLogger("netprobe")

    # Avoid adding duplicate handlers when called more than once
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    console_fmt = ColouredFormatter(
        fmt="[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        use_colour=use_colour,
    )
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            fmt="[%(levelname)s] %(asctime)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger
