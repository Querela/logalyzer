import argparse
import bisect
import gzip
import io
import logging
import os.path
import sys
from abc import ABCMeta, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache, partial
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from pathlib import Path
from pprint import pprint
from typing import Callable, Dict, Generic, List, Literal, TypedDict, TypeVar, overload

from apachelogs import LogParser, InvalidEntryError, LogEntry as ParsedLogEntry

from logalyzer.utils import anyopen

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------

# see: https://github.com/jwodder/apachelogs
# apache log format string
LOG_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LogEntry:
    # %t
    time: str
    # %h
    ipaddress: IPv4Address
    # %>s
    status_code: int
    # "%{Referer}i"
    referer: str | None
    # "%{User-Agent}i"
    user_agent: str

    line_nr: int = -1
    fpos: int = -1

    @staticmethod
    def fromApacheLogEntry(
        entry: ParsedLogEntry, line_nr: int = -1, fpos: int = -1
    ) -> "LogEntry":
        return LogEntry(
            time=entry.directives["%t"],
            ipaddress=IPv4Address(entry.directives["%h"]),
            status_code=entry.directives["%>s"],
            referer=entry.directives["%{Referer}i"],
            user_agent=entry.directives["%{User-Agent}i"],
            line_nr=line_nr,
            fpos=fpos,
        )

    @property
    def has_referer(self):
        return self.referer is not None


# --------------------------------------------------------------------------


def create_log_parser(logformat: str = LOG_FORMAT):
    return LogParser(logformat)


# --------------------------------------------------------------------------



def filter_valid_logfiles(
    files: List[Path],
    parser: LogParser | None = None,
    try_parse_num_lines: int | None = 3,
):
    if parser is None:
        parser = create_log_parser()

    valid_files: List[Path] = []

    for file in files:
        try:
            with anyopen(file, "rt") as fp:
                if try_parse_num_lines is not None and try_parse_num_lines > 0:
                    errors = []
                    num_lines_ok = 0

                    for lno, line in enumerate(fp, 1):
                        try:
                            entry = parser.parse(line)
                            num_lines_ok += 1
                        except InvalidEntryError as ex:
                            errors.append(ex)

                        if lno >= try_parse_num_lines:
                            break

                    if errors:
                        LOGGER.debug(
                            "File with format/parse issues: '%s' - %sx parse errors vs %sx valid lines, tested %sx lines",
                            file,
                            len(errors),
                            num_lines_ok,
                            try_parse_num_lines,
                        )
                        raise errors[0]

            valid_files.append(file)
        except InvalidEntryError as ex:
            LOGGER.warning("File not with correct log format: '%s' - %s", file, ex)
        except Exception as ex:
            LOGGER.warning("Invalid file: %s - %s", file, ex)

    return valid_files


# --------------------------------------------------------------------------


def sort_logfiles(
    files: List[Path],
    by: Literal["filename", "filetime", "first-log-time"] | None = "filename",
    parser: LogParser | None = None,
) -> List[Path]:
    fn_key: Callable[[Path], float | datetime] | None = None

    if by == "filetime":

        def fn_key(file: Path):
            return file.stat().st_mtime

    elif by == "first-log-time":
        if parser is None:
            parser = create_log_parser()

        def fn_key(file: Path):
            try:
                with anyopen(file, "rt") as fp:
                    line = fp.readline()
                    entry = parser.parse(line)
                    return entry.directives["%t"]
            except:
                return None

    else:
        fn_key = None

    # sort by filename
    # sort by filetime
    # sort by first log line timestamp
    return sorted(files, key=fn_key)


# --------------------------------------------------------------------------
