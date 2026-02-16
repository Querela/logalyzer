import bisect
import logging
import os.path
from dataclasses import dataclass, field
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, summarize_address_range
from pathlib import Path
from typing import Dict, List

from logalyzer.utils import anyopen

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# ip / asn lookup


@dataclass(frozen=True, order=True)
class IPv4ASNEntry:
    start: IPv4Address
    end: IPv4Address
    number: int
    country_code: str
    description: str
    networks: List[IPv4Network] = field(default_factory=list, hash=False, compare=False)


class IPv4ASNLookup:
    def __init__(self):
        self.network2asn: Dict[IPv4Network, IPv4ASNEntry] = dict()
        self.search_list: List[IPv4Network] = list()

    def load(self, tsv_file: str | os.PathLike | Path):
        LOGGER.debug(f"Loading IPv4 ASNs from '{tsv_file}'")

        if not os.path.exists(tsv_file):
            raise FileNotFoundError(f"IPv4 ASN mapping file not found: '{tsv_file}'")

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
