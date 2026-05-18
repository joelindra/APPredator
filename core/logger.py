import io
import sys
from typing import Callable, Optional

from loguru import logger


def _try_line_buffer_stdout() -> None:
    """Under piped dev servers (concurrently, CI), stdout is block-buffered; flush per line."""
    try:
        out = sys.stdout
        if hasattr(out, "reconfigure") and callable(getattr(out, "reconfigure")):
            out.reconfigure(line_buffering=True)
    except (OSError, AttributeError, ValueError, io.UnsupportedOperation):
        pass


def setup_logger(verbose: bool = False, extra_sink: Optional[Callable] = None):
    level = "DEBUG" if verbose else "INFO"
    logger.remove()
    _try_line_buffer_stdout()
    logger.add(
        sys.stdout,
        colorize=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
    )
    if extra_sink is not None:
        logger.add(
            extra_sink,
            level=level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
        )
    return logger


def attach_job_log_sink(job_id: str, *, redact: bool = True) -> int:
    """Returns handler id for removal."""
    from core.job_logs import make_loguru_sink

    return logger.add(
        make_loguru_sink(job_id, redact=redact),
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    )


def detach_log_sink(handler_id: int) -> None:
    try:
        logger.remove(handler_id)
    except ValueError:
        pass
