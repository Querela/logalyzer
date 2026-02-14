import io
import logging
from abc import ABCMeta, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache, partial
from ipaddress import IPv4Network
from pathlib import Path
from typing import Dict, Generic, List, Literal, TypeVar, overload


from logalyzer.asn import IPv4ASNLookup, IPv4ASNEntry
from logalyzer.logs import LogEntry
from logalyzer.ratelimit import (
    TokenBucket,
    TokenBucketWithStreakInfo,
    ExceedStreakInformation,
)


# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------

TK = TypeVar("TK")

# --------------------------------------------------------------------------


class LogEntryAnalyzer(metaclass=ABCMeta):
    @abstractmethod
    def process(self, log_entry: LogEntry): ...

    def onNewFile(self, file: Path): ...


class Reportable(metaclass=ABCMeta):
    @abstractmethod
    def report(self, /, stream: io.TextIOBase | None = None, **kwargs): ...


# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------


class ExcessRequestsPerIPv4Analyzer(Reportable, ExcessRequestsPerKeyAnalyzer[str]):
    def bucket_key(self, log_entry: LogEntry):
        return str(log_entry.ipaddress)

    def report(self, /, stream: io.TextIOBase | None = None, **kwargs):
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


class ExcessRequestsPerIPv4ASNAnalyzer(Reportable, ExcessRequestsPerKeyAnalyzer[str]):
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

    def report(self, /, stream: io.TextIOBase | None = None, **kwargs):
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
            sprint(f"- {asn_info.start} -- {asn_info.end}  ASN={asn_info.number!r}")
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


class ExcessRequestsPerIPv4ASNSingleNetAnalyzer(
    Reportable, ExcessRequestsPerKeyAnalyzer[str]
):
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

    def report(self, /, stream: io.TextIOBase | None = None, **kwargs):
        pass


# --------------------------------------------------------------------------
