import logging
import sys
from rich.logging import RichHandler


def get_logger(name: str = "codesentinel") -> logging.Logger:
    """Configures and returns a structured rich logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_path=False
        )
        formatter = logging.Formatter(
            fmt="%(message)s",
            datefmt="[%X]"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger


logger = get_logger("codesentinel")
