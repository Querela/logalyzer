import gzip
import logging
import os
from pathlib import Path
from typing import Literal

# --------------------------------------------------------------------------


def eprint(*values: object, **kwargs):
    print(*values, **kwargs)


# --------------------------------------------------------------------------


def anyopen(
    filename: str | os.PathLike | Path,
    mode: str = "r",
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
    is_compressed: Literal["gzip"] | None = None,
    **kwargs,
):
    filename = str(filename)

    if is_compressed == "gzip" or filename.endswith(".gz"):
        fn_open = gzip.open
        if mode in ("r", "w", "x", "a"):
            mode += "t"
    else:
        fn_open = open

    return fn_open(
        filename,
        mode=mode,
        encoding=encoding,
        errors=errors,
        newline=newline,
        **kwargs,
    )


# --------------------------------------------------------------------------


def setup_logging(verbose: bool | None = None):
    loglevel = logging.INFO
    if verbose is True:
        loglevel = logging.DEBUG
    elif verbose is False:
        loglevel = logging.WARNING

    from rich.logging import RichHandler

    logging.basicConfig(
        format="%(message)s",
        level=loglevel,
        handlers=[
            RichHandler(rich_tracebacks=True, log_time_format="%Y-%m-%d %H:%M:%S")
        ],
    )


# --------------------------------------------------------------------------
