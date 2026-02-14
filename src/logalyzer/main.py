import logging
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
    Reportable,
)
from logalyzer.asn import FN_IPv4ASN_MAP, IPv4ASNLookup
from logalyzer.logs import (
    LogEntry,
    create_log_parser,
    filter_valid_logfiles,
    sort_logfiles,
)
from logalyzer.utils import anyopen

from apachelogs import LogParser, InvalidEntryError

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

    with anyopen(file, "rt") as fp:
        num_errors = 0

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
            except InvalidEntryError:
                # ignore invalid lines (may happen?)
                num_errors += 1
                continue
            finally:
                if can_tell:
                    try:
                        fpos = fp.tell()
                    except OSError:
                        fpos = -1
                        can_tell = False

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

        num_lines = lno

    stats: FileStats = {
        "lines": num_lines,
        "errors": num_errors,
        "uniqIP": len(cntIPs),
        "noReferer": cntHasReferer[False],
    }

    return stats


# --------------------------------------------------------------------------


def main(files: List[Path], debug: bool = False):
    parser = create_log_parser()

    LOGGER.info(f"Load prerequisite data (IPv4 ASN mapping) ...")
    mapIPv4ASN = IPv4ASNLookup()
    mapIPv4ASN.load(FN_IPv4ASN_MAP)

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
    analyzers.append(ExcessRequestsPerIPv4Analyzer(5, 5 / 1))
    analyzers.append(ExcessRequestsPerIPv4ASNAnalyzer(mapIPv4ASN, 10, 10 / 1))
    # analyzers.append(ExcessRequestsPerIPv4ASNSingleNetAnalyzer(mapIPv4ASN, 10, 10/1))

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
