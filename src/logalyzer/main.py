import logging
import os
import sys
from collections import Counter
from pathlib import Path
from pprint import pprint
from typing import Dict, List, TypedDict

from logalyzer.analyzers import (
    LogEntryAnalyzer,
    ExcessRequestsPerIPv4Analyzer,
    ExcessRequestsPerIPv4ASNAnalyzer,
    ExcessRequestsPerIPv4ASNSingleNetAnalyzer,
    ExcessRequestsPerIPv4ASNNumberAnalyzer,
    IPASNCounterAnalyzer,
    IPv4ASNSingleNetCounterAnalyzer,
    IPCounterAnalyzer,
    UserAgentCounterAnalyzer,
    Reportable,
)
from logalyzer.asn import IPv4ASNLookup
from logalyzer.logs import (
    create_log_parser,
    filter_valid_logfiles,
    parse_logs_ordered,
    sort_logfiles,
)

from apachelogs import LogParser

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------


class FileStats(TypedDict):
    lines: int
    errors: int
    uniqIP: int
    noReferer: int


# --------------------------------------------------------------------------


def process_file(
    file: Path,
    analyzers: List[LogEntryAnalyzer],
    parser: LogParser | None = None,
    skip_with_referer: bool = True,
):
    if parser is None:
        parser = create_log_parser()

    for analyzer in analyzers:
        analyzer.onNewFile(file)

    cntIPs = Counter()
    cntHasReferer = Counter()
    num_errors = 0

    logs_iter = parse_logs_ordered(file, parser=parser, yield_errors_as_None=True)
    for idx, entry in enumerate(logs_iter, 1):
        if entry is None:
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

    num_lines = idx

    stats: FileStats = {
        "lines": num_lines,
        "errors": num_errors,
        "uniqIP": len(cntIPs),
        "noReferer": cntHasReferer[False],
    }

    return stats


# --------------------------------------------------------------------------


def main(files: List[Path], ip2asn_file: str | os.PathLike | Path, debug: bool = False):
    parser = create_log_parser()

    LOGGER.info(f"Load prerequisite data (IPv4 ASN mapping) ...")
    mapIPv4ASN = IPv4ASNLookup()
    mapIPv4ASN.load(ip2asn_file)

    # check input files to be apache log file parsable
    valid_files = filter_valid_logfiles(files)
    LOGGER.info(f"Validated input log files. {len(files)} --> {len(valid_files)}")
    files = valid_files

    # sort files
    files = sort_logfiles(files, by="filename")
    if debug:
        pprint(files, stream=sys.stderr)

    file2stats: Dict[str, FileStats] = dict()
    analyzers: List[LogEntryAnalyzer] = list()
    # NOTE: for second resolution, choose a token capacity slightly larger than the refill rate to combine streaks across the seconds boundary!
    # (if same, i.e. 5 tokens capacity with 5 tokens per seconds refill; otherwise each second all tokens will be refilled and excessive requests get lost!)
    analyzers.append(ExcessRequestsPerIPv4Analyzer(6, 5 / 1))
    # analyzers.append(ExcessRequestsPerIPv4Analyzer(5, 1 / 5))
    # analyzers.append(ExcessRequestsPerIPv4Analyzer(30, 25 / 5))
    analyzers.append(ExcessRequestsPerIPv4ASNAnalyzer(mapIPv4ASN, 11, 10 / 1))
    # analyzers.append(ExcessRequestsPerIPv4ASNSingleNetAnalyzer(mapIPv4ASN, 11, 10 / 1))
    # analyzers.append(ExcessRequestsPerIPv4ASNNumberAnalyzer(mapIPv4ASN, 11, 10 / 1))
    analyzers.append(IPCounterAnalyzer())
    # analyzers.append(IPASNCounterAnalyzer(mapIPv4ASN))
    analyzers.append(IPv4ASNSingleNetCounterAnalyzer(mapIPv4ASN))
    # analyzers.append(UserAgentCounterAnalyzer())

    LOGGER.info(
        f"Start processing {len(files)} file{'s' if len(files)!= 1 else ''} ..."
    )

    # process files
    for file in files:
        LOGGER.debug(f"Processing '{file}' ...")
        stats = process_file(file, analyzers=analyzers, parser=parser)
        LOGGER.info(f"Processed '{file}': {stats=}")

        file2stats[str(file)] = stats

    # dump analyzer info to file

    # print reports
    for analyzer in analyzers:
        if isinstance(analyzer, Reportable):
            analyzer.report(stream=sys.stderr)
            print("\n", file=sys.stderr)

        elif debug:
            pprint(
                {
                    key: {"total": exh.count, "series": len(exh.times)}
                    for key, exh in analyzer.ipsExhausted.items()
                },
                stream=sys.stderr,
            )

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


# --------------------------------------------------------------------------
