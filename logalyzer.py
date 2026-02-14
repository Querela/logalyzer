"""
Apache Log Analyzer.

Installation:

    pip install -r requirements.txt
    # NOTE: use virtual environment

Usage:

    python3 logalyzer.py -i '**/*.log*'

Extra data:

    - https://iptoasn.com/data/ip2asn-v4.tsv.gz
        IPv4 ASN lookup
"""

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


# --------------------------------------------------------------------------

LOGGER = logging.getLogger(
    __name__
    if __name__ != "__main__"
    else os.path.splitext(os.path.basename(__file__))[0]
)

base = os.path.dirname(__file__)
relbase = os.getcwd()

DN_BASE = os.path.relpath(os.path.join(base, "."), relbase)
FN_IPv4ASN_MAP = os.path.join(DN_BASE, "ip2asn-v4.tsv")

# see: https://github.com/jwodder/apachelogs
# apache log format string
LOG_FORMAT = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'

# --------------------------------------------------------------------------
# utils


def eprint(*values: object, **kwargs):
    print(*values, **kwargs)


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
# vendor?


# --------------------------------------------------------------------------
# types


class FileStats(TypedDict):
    lines: int
    errors: int
    uniqIP: int
    noReferer: int


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

    @staticmethod
    def fromApacheLogEntry(entry: ParsedLogEntry) -> "LogEntry":
        return LogEntry(
            time=entry.directives["%t"],
            ipaddress=IPv4Address(entry.directives["%h"]),
            status_code=entry.directives["%>s"],
            referer=entry.directives["%{Referer}i"],
            user_agent=entry.directives["%{User-Agent}i"],
        )

    @property
    def has_referer(self):
        return self.referer is not None


# --------------------------------------------------------------------------
# rate limiter / token bucket


class TokensExhausted(Exception):
    pass


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float, last_refill: float = 0):
        #: total allowed tokens
        self.capacity = capacity
        #: number of tokens left in current window
        self.tokens = capacity
        #: how many tokens we refill (in tokens per second)
        self.refill_rate = refill_rate
        #: timestamp (UNIX) from last refill
        self.last_refill: float = 0

    @staticmethod
    def when(at: float | datetime | None = None):
        if at is None:
            at = datetime.now()
        if isinstance(at, datetime):
            at = at.timestamp()
        return at

    def refill(self, at: float | datetime | None = None):
        at = self.when(at)

        # compute elapsed time between last refill and current (at) time
        elapsed = at - self.last_refill
        # how many new tokens to fill in bucket
        new_tokens = elapsed * self.refill_rate

        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = at

    def consume(
        self,
        tokens: float = 1,
        at: float | datetime | None = None,
        raise_exc: bool = True,
    ):
        at = self.when(at)
        self.refill(at=at)

        tokens_left = self.tokens - tokens
        self.tokens = max(0, tokens_left)  # can we overdraw?

        if tokens_left < 0:
            if raise_exc:
                raise TokensExhausted()
            return False
        return True

    def can_consume(self, tokens: float = 1, at: float | datetime | None = None):
        self.refill(at=at)

        tokens_left = self.tokens - tokens

        return tokens_left >= 0

    def __repr__(self):
        return (
            self.__class__.__qualname__
            + f"(capacity={self.capacity!r}, tokens={self.tokens!r}, refill_rate={self.refill_rate!r}, last_refill={self.last_refill!r})"
        )


@dataclass
class ExceedStreakInformation:
    # UNIX timestamps (convertable to `datetime`)
    start: float
    end: float | None = None
    start_exceed: float | None = None
    end_exceed: float | None = None
    count: int = 0
    count_exceed: int = 0

    @property
    def has_exceeded(self):
        return self.count_exceed > 0

    def update(self, when: float, exceeded: bool):
        # update last known end of any information
        self.end = when
        # increment all
        self.count += 1

        if exceeded:
            # if we do not yet have a start, set the start of exceeding
            if self.start_exceed is None:
                self.start_exceed = when
            # last known timestamp of exceeding
            self.end_exceed = when
            # increment
            self.count_exceed += 1

    def __str__(self):
        _ts = datetime.fromtimestamp
        parts = [
            f"{_ts(self.start)} -- {_ts(self.end)}",
            f" [{self.count}x]",
        ]
        if self.start_exceed is not None:
            parts.extend(
                [
                    f", exceeded: {_ts(self.start_exceed)} -- {_ts(self.end_exceed)}",
                    f" [{self.count_exceed}x]",
                ]
            )
        return "".join(parts)


class TokenBucketWithStreakInfo(TokenBucket):
    def __init__(self, capacity: float, refill_rate: float, last_refill: float = 0):
        super().__init__(capacity, refill_rate, last_refill)
        self.streak: ExceedStreakInformation | None = None

    def refill(self, at: float | datetime | None = None):
        # refill bucket
        super().refill(at)

        # check if bucket if full
        bucket_full = self.tokens == self.capacity
        # bucket is full, previous streak can be discarded, start (possible) new streak
        if bucket_full:
            # if self.streak is not None and self.streak.start_exceed is not None:
            #     LOGGER.debug(f"Streak: {self.streak}")
            at = self.when(at)
            self.streak = ExceedStreakInformation(start=at)

    def consume(
        self,
        tokens: float = 1,
        at: float | datetime | None = None,
        raise_exc: bool = True,
    ):
        at = self.when(at)
        # True if tokens left, False if tokens exhausted/request limit exceeded
        tokens_left = True
        try:
            tokens_left = super().consume(tokens, at=at, raise_exc=raise_exc)
        except TokensExhausted as ex:
            tokens_left = False
            raise ex
        finally:
            # if first request
            if self.streak is None:
                self.streak = ExceedStreakInformation(start=at)

            # update streak "end" times
            self.streak.update(at, exceeded=not tokens_left)
            # NOTE: excessive requests may reduce for a time and later increase again
            # will all be in the same streak if token bucket has no change to fully recover

        return tokens_left

    def __repr__(self):
        return (
            self.__class__.__qualname__
            + f"(capacity={self.capacity!r}, tokens={self.tokens!r}, refill_rate={self.refill_rate!r}, last_refill={self.last_refill!r}, streak={self.streak!r})"
        )


# --------------------------------------------------------------------------
# ip / asn lookup


@dataclass(frozen=True)
class IPv4ASNEntry:
    start: IPv4Address
    end: IPv4Address
    number: int
    country_code: str
    description: str
    networks: List[IPv4Network] = field(default_factory=list)


class IPv4ASNLookup:
    def __init__(self):
        self.network2asn: Dict[IPv4Network, IPv4ASNEntry] = dict()
        self.search_list: List[IPv4Network] = list()

    def load(self, tsv_file: str | os.PathLike | Path):
        LOGGER.debug(f"Loading IPv4 ASNs from '{tsv_file}'")

        with anyopen(tsv_file, "rt") as fp:
            for lno, line in enumerate(fp):
                parts = line.rstrip().split("\t")
                assert len(parts) == 5
                range_start, range_end, AS_number, country_code, AS_description = parts

                ip_start = IPv4Address(range_start)
                ip_end = IPv4Address(range_end)
                ip_nets = list(summarize_address_range(ip_start, ip_end))
                assert (
                    ip_start == ip_nets[0].network_address
                    and ip_end == ip_nets[-1].broadcast_address
                ), f"{ip_start=} {ip_end=} {ip_nets=}"

                entry = IPv4ASNEntry(
                    start=ip_start,
                    end=ip_end,
                    number=int(AS_number),
                    country_code=country_code,
                    description=AS_description,
                    networks=ip_nets,
                )

                for ip_net in ip_nets:
                    search_address = ip_net.network_address
                    self.network2asn[search_address] = entry
                    self.search_list.append(search_address)

        self.search_list.sort()  # TODO: `bisect` insert?

        LOGGER.debug(f"Read {lno+1} IPv4 ASNs entries.")
        LOGGER.debug(
            f"Generated {len(self.search_list)} IPv4 network address search entries."
        )

    @lru_cache(maxsize=2**10)
    def find_net(self, ipaddress: str | IPv4Address) -> IPv4Network:
        if not isinstance(ipaddress, IPv4Address):
            ipaddress = IPv4Address(ipaddress)

        idx = bisect.bisect_right(self.search_list, ipaddress)

        if idx and (idx - 1) >= 0 and idx < len(self.search_list):
            base_address = self.search_list[idx - 1]
            entry = self.network2asn[base_address]

            # this should never happen
            assert (
                entry.end >= ipaddress
            ), f"IPv4Address {ipaddress} not in known range."

            for ip_net in entry.networks:
                if base_address == ip_net.network_address:
                    return ip_net

        # TODO: or fail?
        return IPv4Network(ipaddress)

    @lru_cache(maxsize=2**10)
    def find_asn(self, ipaddress: IPv4Address | IPv4Network):
        # if ip address -> find ASN network
        if isinstance(ipaddress, IPv4Address):
            ip_net = self.find_net(ipaddress)

        # if ip network -> convert to ip network address
        elif isinstance(ipaddress, IPv4Network):
            # NOTE: this might not exist in self.network2asn, so we do a .find_net() again
            if ipaddress.network_address not in self.network2asn:
                ip_net = self.find_net(ipaddress.network_address)
            else:
                ip_net = ipaddress

        else:
            # maybe str -> IPv4Network?
            raise ValueError(f"Unsupported type: {type(ipaddress)}")

        entry = self.network2asn[ip_net.network_address]
        return entry

    # TODO: maybe reverse dependency between find_net and find_asn?


# --------------------------------------------------------------------------


TK = TypeVar("TK")


class LogEntryAnalyzer(metaclass=ABCMeta):
    @abstractmethod
    def process(self, log_entry: LogEntry): ...

    def onNewFile(self, file: Path): ...

    def report(self, stream=None): ...


@dataclass
class ExhaustedEntry:
    count: int = 0
    times: List[datetime] = field(default_factory=list)
    items: Counter = field(default_factory=Counter)
    recovered: bool = True


class ExcessRequestsPerKeyAnalyzer(Generic[TK], LogEntryAnalyzer, metaclass=ABCMeta):
    def __init__(
        self,
        token_capacity: float,
        token_refill_rate: float,
        token_consuption: float = 1,
        only_track_first_in_series: bool = True,
    ):
        super().__init__()

        self.token_capacity = token_capacity
        self.token_refill_rate = token_refill_rate
        self.token_consuption = token_consuption

        self.token_buckets: Dict[TK, TokenBucket] = dict()
        self.ipsExhausted: Dict[TK, ExhaustedEntry] = dict()
        self.exceed_streak: Dict[TK, List[ExceedStreakInformation]] = dict()

        self.only_track_first_in_series = only_track_first_in_series

    @abstractmethod
    def bucket_key(self, log_entry: LogEntry) -> TK: ...

    @lru_cache
    def _bucket_key(self, log_entry: LogEntry):
        return self.bucket_key(log_entry)

    def _bucket_factory(self):
        factory_cls = TokenBucket
        factory_cls = TokenBucketWithStreakInfo
        token_bucket = factory_cls(
            capacity=self.token_capacity,
            refill_rate=self.token_refill_rate,
        )
        return token_bucket

    def _get_bucket(self, log_entry: LogEntry):
        key = self._bucket_key(log_entry)
        try:
            return self.token_buckets[key]
        except KeyError:
            token_bucket = self._bucket_factory()
            self.token_buckets[key] = token_bucket
            return token_bucket

    def _get_exceed_streak_info(self, log_entry: LogEntry):
        key = self._bucket_key(log_entry)

        streak_list = self.exceed_streak.get(key, None)
        if streak_list is None:
            streak_list = []
            self.exceed_streak[key] = streak_list

        return streak_list

    def _update_exceed_streak(self, log_entry: LogEntry):
        token_bucket = self._get_bucket(log_entry)
        if not isinstance(token_bucket, TokenBucketWithStreakInfo):
            return

        streak = token_bucket.streak
        if not streak.has_exceeded:
            # only interested if exceeded, otherwise noise/default behaviour
            return

        streak_list = self._get_exceed_streak_info(log_entry)
        if not streak_list:
            # if new, then simply add
            streak_list.append(streak)
            return

        # check if not already recorded
        last_streak = streak_list[-1]
        if last_streak.start != streak.start:
            streak_list.append(streak)

    @overload
    def _get_exhaustion_state(
        self, log_entry: LogEntry, create: Literal[True] = True
    ) -> ExhaustedEntry: ...
    @overload
    def _get_exhaustion_state(
        self, log_entry: LogEntry, create: Literal[False] = False
    ) -> ExhaustedEntry | None: ...
    def _get_exhaustion_state(self, log_entry: LogEntry, create: bool = True):
        key = self._bucket_key(log_entry)

        state = self.ipsExhausted.get(key, None)
        if state is None and create:
            state = ExhaustedEntry()
            self.ipsExhausted[key] = state

        return state

    def _add_exhaustion(self, log_entry: LogEntry):
        key = self._bucket_key(log_entry)
        state = self._get_exhaustion_state(log_entry, create=True)

        state.count += 1
        # customizable
        self.update_exhaustion_info(log_entry, state, log_entry_key=key)

        if self.only_track_first_in_series:
            # if requests were ok, we now block since exceeded
            if state.recovered:
                state.recovered = False

            # if requests exceeded and we did not recover, do not track time object again
            else:
                return

        state.times.append(log_entry.time)

    def _reset_exhaustion_for_ip(self, log_entry: LogEntry):
        state = self._get_exhaustion_state(log_entry, create=False)
        if state is not None:
            state.recovered = True

    def update_exhaustion_info(
        self,
        log_entry: LogEntry,
        exhaustion_entry: ExhaustedEntry,
        log_entry_key: TK,
    ):
        exhaustion_entry.items[log_entry_key] += 1

    def process(self, log_entry: LogEntry):
        token_bucket = self._get_bucket(log_entry)
        ok = token_bucket.consume(
            tokens=self.token_consuption,
            at=log_entry.time,
            raise_exc=False,
        )

        # update streak information
        self._update_exceed_streak(log_entry)

        # update exhaustion
        if not ok:
            self._add_exhaustion(log_entry)
        else:
            self._reset_exhaustion_for_ip(log_entry)

    @abstractmethod
    def report(self, stream=None): ...


class ExcessRequestsPerIPv4Analyzer(ExcessRequestsPerKeyAnalyzer[str]):
    def bucket_key(self, log_entry: LogEntry):
        return str(log_entry.ipaddress)

    def report(self, stream: io.TextIOBase | None = None):
        sprint = partial(print, file=stream)
        sprint("# Excessive IPv4 Requests")

        dummy_tb = self._bucket_factory()
        ratio = dummy_tb.refill_rate.as_integer_ratio()
        sprint(
            f"- rate limiting with TokenBucket"
            f": capacity={dummy_tb.capacity!r}, refill_rate={dummy_tb.refill_rate!r}"
            f" ({ratio[0]} req / {ratio[1]} sec)"
        )

        sprint()
        sprint("## Request streaks per IP")
        if not self.exceed_streak:
            sprint("-> No limits exceeded!")
            return

        for ip, streaks in self.exceed_streak.items():
            sprint(f"- {ip}")
            for streak in streaks:
                sprint(f"  - {streak!s}")
            sprint(
                f"  -> total requests = {sum(s.count for s in streaks)}"
                f", after limit reached = {sum(s.count_exceed for s in streaks)}"
            )


class ExcessRequestsPerIPv4ASNAnalyzer(ExcessRequestsPerKeyAnalyzer[str]):
    def __init__(
        self,
        asn_lookup: IPv4ASNLookup,
        token_capacity: float,
        token_refill_rate: float,
        token_consuption: float = 1,
        only_track_first_in_series: bool = True,
    ):
        super().__init__(
            token_capacity,
            token_refill_rate,
            token_consuption,
            only_track_first_in_series,
        )
        self.asn_lookup = asn_lookup
        self.key2asn: Dict[str, IPv4ASNEntry] = dict()

    def bucket_key(self, log_entry: LogEntry):
        asn_info = self.asn_lookup.find_asn(log_entry.ipaddress)
        key = f"{asn_info.start!s}--{asn_info.end!s}"

        # store key to ASN for later
        self.key2asn[key] = asn_info

        return key

    def report(self, stream: io.TextIOBase | None = None):
        sprint = partial(print, file=stream)
        sprint("# Excessive IPv4 ASN Requests")

        dummy_tb = self._bucket_factory()
        ratio = dummy_tb.refill_rate.as_integer_ratio()
        sprint(
            f"- rate limiting with TokenBucket"
            f": capacity={dummy_tb.capacity!r}, refill_rate={dummy_tb.refill_rate!r}"
            f" ({ratio[0]} req / {ratio[1]} sec)"
        )

        sprint()
        sprint("## Request streaks per IP Range")
        if not self.exceed_streak:
            sprint("-> No limits exceeded!")
            return

        for key, streaks in self.exceed_streak.items():
            asn_info = self.key2asn[key]
            sprint(f"- {key} ASN={asn_info.number!r}")
            sprint(f"  -> [{asn_info.country_code}] {asn_info.description}")
            sprint(
                f"  -> networks: {', '.join(map(str, (ipnet for ipnet in asn_info.networks)))}"
            )
            for streak in streaks:
                sprint(f"  - {streak!s}")
            sprint(
                f"  -> total requests = {sum(s.count for s in streaks)}"
                f", after limit reached = {sum(s.count_exceed for s in streaks)}"
            )


class ExcessRequestsPerIPv4ASNSingleNetAnalyzer(ExcessRequestsPerKeyAnalyzer[str]):
    def __init__(
        self,
        asn_lookup: IPv4ASNLookup,
        token_capacity: float,
        token_refill_rate: float,
        token_consuption: float = 1,
        only_track_first_in_series: bool = True,
    ):
        super().__init__(
            token_capacity,
            token_refill_rate,
            token_consuption,
            only_track_first_in_series,
        )
        self.asn_lookup = asn_lookup
        self.key2net: Dict[str, IPv4Network] = dict()

    def bucket_key(self, log_entry: LogEntry):
        ip_net = self.asn_lookup.find_net(log_entry.ipaddress)
        key = f"{ip_net!s}"

        # store key to ASN for later
        self.key2asn[key] = ip_net

        return key

    def report(self, stream: io.TextIOBase | None = None):
        pass


# --------------------------------------------------------------------------


def filter_valid_logfiles(
    files: List[Path],
    parser: LogParser | None = None,
    try_parse_num_lines: int | None = 3,
):
    if parser is None:
        parser = LogParser(LOG_FORMAT)

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
            parser = LogParser(LOG_FORMAT)

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


def process_file(
    file: Path,
    analyzers: List[LogEntryAnalyzer],
    parser: LogParser | None = None,
    skip_with_referer: bool = True,
):
    if parser is None:
        parser = LogParser(LOG_FORMAT)

    for analyzer in analyzers:
        analyzer.onNewFile(file)

    cntIPs = Counter()
    cntHasReferer = Counter()

    with anyopen(file, "rt") as fp:
        num_errors = 0
        for lno, line in enumerate(fp):
            try:
                entry_raw = parser.parse(line)
                entry = LogEntry.fromApacheLogEntry(entry_raw)
            except InvalidEntryError:
                # ignore invalid lines (may happen?)
                num_errors += 1
                continue

            ip = str(entry.ipaddress)
            has_referer = entry.has_referer

            cntIPs[ip] += 1
            cntHasReferer[has_referer] += 1

            # possible filters
            if skip_with_referer and has_referer:
                continue

            # actual analysis
            for analyzer in analyzers:
                analyzer.process(entry)

        num_lines = lno + 1

    stats: FileStats = {
        "lines": num_lines,
        "errors": num_errors,
        "uniqIP": len(cntIPs),
        "noReferer": cntHasReferer[False],
    }

    return stats


def main(files: List[Path]):
    parser = LogParser(LOG_FORMAT)
    mapIPv4ASN = IPv4ASNLookup()
    mapIPv4ASN.load(FN_IPv4ASN_MAP)

    # check input files to be apache log file parsable
    valid_files = filter_valid_logfiles(files)
    LOGGER.debug(f"Validated input log files. {len(files)} --> {len(valid_files)}")
    files = valid_files

    # sort files
    files = sort_logfiles(files, by="filename")
    if LOGGER.isEnabledFor(logging.DEBUG):
        pprint(files, stream=sys.stderr)

    file2stats: Dict[str, FileStats] = dict()
    analyzers: List[LogEntryAnalyzer] = list()
    analyzers.append(ExcessRequestsPerIPv4Analyzer(5, 5 / 1))
    analyzers.append(ExcessRequestsPerIPv4ASNAnalyzer(mapIPv4ASN, 10, 10 / 1))
    # analyzers.append(ExcessRequestsPerIPv4ASNSingleNetAnalyzer(mapIPv4ASN, 10, 10/1))

    # process files
    for file in files:

        LOGGER.debug(f"Processing '{file}' ...")
        stats = process_file(file, analyzers=analyzers, parser=parser)
        LOGGER.info(f"Processed '{file}': {stats=}")

        file2stats[str(file)] = stats

    analyzers[0].report(stream=sys.stderr)
    print("\n", file=sys.stderr)
    analyzers[1].report(stream=sys.stderr)

    # pprint(
    #     {
    #         ip: {"total": exh.count, "series": len(exh.times)}
    #         for ip, exh in analyzers[0].ipsExhausted.items()
    #     }
    # )

    # pprint(
    #     {
    #         ip: bucket.streak
    #         for ip, bucket in analyzers[0].token_buckets.items()
    #         if ip in analyzers[0].ipsExhausted
    #     }
    # )

    # pprint(
    #     {
    #         ip: streaks
    #         for ip, streaks in analyzers[0].exceed_streak.items()
    #         if ip in analyzers[0].ipsExhausted
    #     }
    # )

    # pprint(
    #     {
    #         asn: {"total": exh.count, "series": len(exh.times)}
    #         for asn, exh in analyzers[1].ipsExhausted.items()
    #     }
    # )
    # pprint(
    #     {
    #         net: {"total": exh.count, "series": len(exh.times)}
    #         for net, exh in analyzers[2].ipsExhausted.items()
    #     }
    # )


# --------------------------------------------------------------------------
# cli


@lru_cache(maxsize=1)
def _has_rich():
    try:
        import rich
    except ImportError:
        return False
    return True


def setup_logging(debug: bool = False):
    loglevel = logging.DEBUG if debug else logging.INFO

    if _has_rich():
        from rich.logging import RichHandler

        logging.basicConfig(
            format="%(message)s",
            level=loglevel,
            handlers=[
                RichHandler(rich_tracebacks=True, log_time_format="%Y-%m-%d %H:%M:%S")
            ],
        )

    else:
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", level=loglevel
        )


def parse_args(args=None):
    self_script_filename = Path(__file__).name

    def paths_pattern_type(value: str):
        try:
            paths = [
                p
                for p in Path(".").glob(value)
                if p.is_file() and p.name != self_script_filename
            ]
        except ValueError as ex:
            # ValueError: Unacceptable pattern: ''
            raise ex
        except IndexError as ex:
            raise ValueError("Invalid glob pattern?") from ex
        return paths

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--debug", action="store_true", default=False, help="Debug output"
    )

    # input: filter filename
    parser.add_argument(
        "-i",
        "--inputs",
        dest="files",
        type=paths_pattern_type,
        required=True,
        help=(
            "Unix style pathname pattern for log files selection."
            " Enclose in quotes to avoid expansion by shell."
        ),
    )

    args = parser.parse_args(args)

    return args


if __name__ == "__main__":
    args = parse_args()

    setup_logging(debug=args.debug)

    if LOGGER.isEnabledFor(logging.DEBUG):
        pprint(args.__dict__, stream=sys.stderr)

    main(files=args.files)
