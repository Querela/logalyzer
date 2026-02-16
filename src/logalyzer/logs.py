import logging
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from queue import PriorityQueue
from typing import Callable, Generator, List, Literal, overload

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
    time: datetime
    # %h
    ipaddress: IPv4Address
    # %>s
    status_code: int
    # "%{Referer}i"
    referer: str | None
    # "%{User-Agent}i"
    user_agent: str | None

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

# to work with out-of-order entries, buffer and sort entries before we process them
# see: https://stackoverflow.com/a/1032022/9360161


@dataclass(frozen=True, eq=False)
class PriorityQueueItem:
    time: float
    entry: LogEntry

    # compare methods as done in dataclasses module
    # we only want to compare the time field

    def __eq__(self, other):
        if other.__class__ is self.__class__:
            return self.time == other.time
        return NotImplemented

    def __lt__(self, other):
        if other.__class__ is self.__class__:
            return self.time < other.time
        return NotImplemented

    def __gt__(self, other):
        if other.__class__ is self.__class__:
            return self.time > other.time
        return NotImplemented

    def __le__(self, other):
        if other.__class__ is self.__class__:
            return self.time <= other.time
        return NotImplemented

    def __ge__(self, other):
        if other.__class__ is self.__class__:
            return self.time >= other.time
        return NotImplemented


@overload
def parse_logs_ordered(
    file: Path,
    parser: LogParser | None = None,
    buffer_size: int = 100,
    yield_errors_as_None: Literal[False] = False,
) -> Generator[LogEntry, None, None]: ...
@overload
def parse_logs_ordered(
    file: Path,
    parser: LogParser | None = None,
    buffer_size: int = 100,
    yield_errors_as_None: Literal[True] = True,
) -> Generator[LogEntry | None, None, None]: ...


def parse_logs_ordered(
    file: Path,
    parser: LogParser | None = None,
    buffer_size: int = 100,
    yield_errors_as_None: bool = True,
) -> Generator[LogEntry | None, None, None]:
    if parser is None:
        parser = create_log_parser()

    # buffer and sort entries by datetime (UNIX timestamp)
    pq = PriorityQueue()
    do_buffer = buffer_size > 0

    with anyopen(file, "rt") as fp:
        # can we determine the current file pointer position
        can_tell = True
        try:
            fpos = fp.tell()
        except OSError:
            fpos = -1
            can_tell = False

        for lno, line in enumerate(fp, 1):
            try:
                entry_raw = parser.parse(line)
                entry = LogEntry.fromApacheLogEntry(entry_raw, line_nr=lno, fpos=fpos)
                if do_buffer:
                    pq.put(PriorityQueueItem(time=entry.time.timestamp(), entry=entry))
                else:
                    yield entry

            except InvalidEntryError:
                # NOTE ignore invalid lines (may happen due to aborted/concurrent writes?)
                # immediately return this error value
                if yield_errors_as_None:
                    yield None

            finally:
                if can_tell:
                    # can we determine the current file pointer position
                    # check again, may fail later (gzip, after first read)
                    try:
                        fpos = fp.tell()
                    except OSError:
                        fpos = -1
                        can_tell = False

                # drain one if buffer full
                if do_buffer:
                    if not pq.empty() and pq.qsize() >= buffer_size:
                        item = pq.get()
                        yield item.entry

    # drain rest
    if do_buffer:
        while not pq.empty():
            item = pq.get()
            yield item.entry


# --------------------------------------------------------------------------
