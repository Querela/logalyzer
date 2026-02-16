import io
import logging
from abc import ABCMeta, abstractmethod
from collections import Counter
from functools import partial
from ipaddress import IPv4Network
from typing import Dict, Generic, List, Set, TypeVar


from logalyzer.asn import IPv4ASNLookup, IPv4ASNEntry
from logalyzer.logs import LogEntry
from logalyzer.analyzers.base import LogEntryAnalyzer, Reportable


# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------

TK = TypeVar("TK")

# --------------------------------------------------------------------------


class CounterPerKeyAnalyzer(Generic[TK], LogEntryAnalyzer, metaclass=ABCMeta):
    def __init__(self):
        super().__init__()

        self.counter: Counter[TK] = Counter()

    @abstractmethod
    def entry_key(self, log_entry: LogEntry) -> TK: ...

    def _key(self, log_entry: LogEntry):
        return self.entry_key(log_entry)

    def process(self, log_entry: LogEntry):
        key = self._key(log_entry)
        self.counter[key] += 1


# --------------------------------------------------------------------------


class IPCounterAnalyzer(Reportable, CounterPerKeyAnalyzer[str]):
    def entry_key(self, log_entry: LogEntry):
        return str(log_entry.ipaddress)

    def report(
        self,
        /,
        stream: io.TextIOBase | None = None,
        topn: int | None = 100,
        min_count: int | None = 3,
        **kwargs,
    ):
        sprint = partial(print, file=stream)
        sprint(f"# Top-Ranked IPv4 by Requests")
        sprint(f"-> {topn=} (IPs), {min_count=} (requests per IP)")

        total = self.counter.total()
        sprint(f"-> {total} requests by {len(self.counter)} IPv4 addresses")
        sprint()

        padlen = max(2, len(str(total)))  # or math.floor(math.log10(total)) + 1
        for ip, cnt in self.counter.most_common(topn):
            if cnt is not None and cnt < min_count:
                continue
            sprint(f"- [{cnt:>{padlen}d}]  {ip}")


class IPASNCounterAnalyzer(Reportable, CounterPerKeyAnalyzer[str]):
    def __init__(self, asn_lookup: IPv4ASNLookup):
        super().__init__()

        self.asn_lookup = asn_lookup
        self.key2asn: Dict[str, IPv4ASNEntry] = dict()

    def entry_key(self, log_entry: LogEntry):
        asn_info = self.asn_lookup.find_asn(log_entry.ipaddress)
        key = f"{asn_info.start!s}--{asn_info.end!s}"

        # store key to ASN for later
        self.key2asn[key] = asn_info

        return key

    def report(
        self,
        /,
        stream: io.TextIOBase | None = None,
        topn: int | None = 100,
        min_count: int | None = 3,
        groupby_asn: bool = True,
        **kwargs,
    ):
        sprint = partial(print, file=stream)
        sprint(f"# Top-Ranked IPv4 ASNs by Requests")
        sprint(f"-> {topn=} (ASNs), {min_count=} (requests per ASN)")

        total = self.counter.total()
        sprint(f"-> {total} requests by {len(self.counter)} IPv4 addresses")
        sprint()

        padlen = max(2, len(str(total)))  # or math.floor(math.log10(total)) + 1

        if groupby_asn:

            mapASNkey2keys: Dict[str, List[str]] = dict()
            mapASNkey2ASNs: Dict[str, IPv4ASNEntry] = dict()
            cntASNkey: Counter[str] = Counter()
            validKeys: Set[str] = set()

            # group by asn_key (ASN description)
            for idx, (key, cnt) in enumerate(self.counter.most_common(), 1):
                do_not_output = False
                if topn is not None and idx > topn:
                    do_not_output = True
                if cnt is not None and cnt < min_count:
                    do_not_output = True

                asn_info = self.key2asn[key]
                asn_key = (
                    f"{asn_info.number}|{asn_info.country_code}|{asn_info.description}"
                )

                if not do_not_output:
                    validKeys.add(key)

                cntASNkey[asn_key] += cnt
                mapASNkey2ASNs[asn_key] = asn_info
                try:
                    mapASNkey2keys[asn_key].append(key)
                except KeyError:
                    mapASNkey2keys[asn_key] = [key]

            padlenKeys = max(1, len(str(max(map(len, mapASNkey2keys.values())))))

            # print grouped
            for asn_key, asn_cnt in cntASNkey.most_common():
                keys = mapASNkey2keys[asn_key]
                # check if all the keys are "invalid" (truncated from output)
                if not any(key in validKeys for key in keys):
                    continue

                asn_info = mapASNkey2ASNs[asn_key]
                sprint(
                    f"## [{asn_cnt:>{padlen}d}] {{{len(keys):>{padlenKeys}d}x}}  ASN={asn_info.number!r}  [{asn_info.country_code}] {asn_info.description}"
                )

                for key in keys:
                    if key not in validKeys:
                        continue

                    cnt = self.counter[key]
                    asn_info = self.key2asn[key]
                    sprint(f"-  [{cnt:>{padlen}d}]  {asn_info.start} -- {asn_info.end}")

                sprint()

        else:

            for key, cnt in self.counter.most_common(topn):
                if cnt is not None and cnt < min_count:
                    continue

                asn_info = self.key2asn[key]

                sprint(
                    f"- [{cnt:>{padlen}d}]  {asn_info.start} -- {asn_info.end}  ASN={asn_info.number!r}"
                )
                sprint(
                    f"  {' '*(padlen+2)}  -> [{asn_info.country_code}] {asn_info.description}"
                )


class IPv4ASNSingleNetCounterAnalyzer(Reportable, CounterPerKeyAnalyzer[str]):
    def __init__(self, asn_lookup: IPv4ASNLookup):
        super().__init__()

        self.asn_lookup = asn_lookup
        self.key2net: Dict[str, IPv4Network] = dict()

    def entry_key(self, log_entry: LogEntry):
        ip_net = self.asn_lookup.find_net(log_entry.ipaddress)
        key = f"{ip_net!s}"

        # store key to ASN for later
        self.key2net[key] = ip_net

        return key

    def report(
        self,
        /,
        stream: io.TextIOBase | None = None,
        topn: int | None = 100,
        min_count: int | None = 3,
        groupby_asn: bool = True,
        **kwargs,
    ):
        sprint = partial(print, file=stream)
        sprint(f"# Top-Ranked IPv4 ASN Networks by Requests")
        sprint(
            f"-> {topn=} (ASN IP Networks), {min_count=} (requests per ASN IP Network)"
        )

        total = self.counter.total()
        sprint(f"-> {total} requests by {len(self.counter)} IPv4 addresses")
        sprint()

        padlen = max(2, len(str(total)))  # or math.floor(math.log10(total)) + 1

        if groupby_asn:

            mapASNkey2keys: Dict[str, List[str]] = dict()
            mapASNkey2ASNs: Dict[str, IPv4ASNEntry] = dict()
            cntASNkey: Counter[str] = Counter()
            validKeys: Set[str] = set()

            # group by asn_key (ASN description)
            for idx, (key, cnt) in enumerate(self.counter.most_common(), 1):
                do_not_output = False
                if topn is not None and idx > topn:
                    do_not_output = True
                if cnt is not None and cnt < min_count:
                    do_not_output = True

                if cnt is not None and cnt < min_count:
                    continue

                ip_net = self.key2net[key]
                asn_info = self.asn_lookup.find_asn(ip_net.network_address)
                asn_key = (
                    f"{asn_info.number}|{asn_info.country_code}|{asn_info.description}"
                )

                if not do_not_output:
                    validKeys.add(key)

                cntASNkey[asn_key] += cnt
                mapASNkey2ASNs[asn_key] = asn_info
                try:
                    mapASNkey2keys[asn_key].append(key)
                except KeyError:
                    mapASNkey2keys[asn_key] = [key]

            padlenKeys = max(1, len(str(max(map(len, mapASNkey2keys.values())))))

            # print grouped
            for asn_key, asn_cnt in cntASNkey.most_common():
                keys = mapASNkey2keys[asn_key]
                # check if all the keys are "invalid" (truncated from output)
                if not any(key in validKeys for key in keys):
                    continue

                asn_info = mapASNkey2ASNs[asn_key]
                sprint(
                    f"## [{asn_cnt:>{padlen}d}] {{{len(keys):>{padlenKeys}d}x}}  ASN={asn_info.number!r}  [{asn_info.country_code}] {asn_info.description}"
                )

                for key in keys:
                    if key not in validKeys:
                        continue

                    cnt = self.counter[key]
                    ip_net = self.key2net[key]
                    asn_info = self.asn_lookup.find_asn(ip_net.network_address)
                    sprint(f"-  [{cnt:>{padlen}d}]  {ip_net}")

                sprint()

        else:

            for key, cnt in self.counter.most_common(topn):
                if cnt is not None and cnt < min_count:
                    continue

                ip_net = self.key2net[key]
                asn_info = self.asn_lookup.find_asn(ip_net.network_address)

                sprint(f"- [{cnt:>{padlen}d}]  {ip_net}  ASN={asn_info.number!r}")
                sprint(
                    f"  {' '*(padlen+2)}  -> [{asn_info.country_code}] {asn_info.description}"
                )


# --------------------------------------------------------------------------


class UserAgentCounterAnalyzer(Reportable, CounterPerKeyAnalyzer[str | None]):
    def entry_key(self, log_entry: LogEntry):
        return log_entry.user_agent

    def report(
        self,
        /,
        stream: io.TextIOBase | None = None,
        topn: int | None = 100,
        min_count: int | None = 3,
        **kwargs,
    ):
        sprint = partial(print, file=stream)
        sprint(f"# Top-Ranked User-Agents by Requests")
        sprint(f"-> {topn=} (user-agents), {min_count=} (requests per user-agent)")

        total = self.counter.total()
        sprint(f"-> {total} requests by {len(self.counter)} user-agents")
        sprint()

        padlen = max(2, len(str(total)))  # or math.floor(math.log10(total)) + 1
        for user_agent, cnt in self.counter.most_common(topn):
            if cnt is not None and cnt < min_count:
                continue
            sprint(f"- [{cnt:>{padlen}d}]  {user_agent!r}")


# --------------------------------------------------------------------------
