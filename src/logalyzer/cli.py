import argparse
import logging
import os.path
import sys
from pathlib import Path
from pprint import pprint

from logalyzer.env import FN_IPv4ASN_MAP
from logalyzer.utils import setup_logging

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(
    __name__
    if __name__ != "__main__"
    else os.path.splitext(os.path.basename(__file__))[0]
)

# --------------------------------------------------------------------------


def parse_args(args=None):
    # self_script_filename = Path(__file__).name

    def paths_pattern_type(value: str):
        try:
            paths = [
                p
                for p in Path(".").glob(value)
                if p.is_file()  # and p.name != self_script_filename
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

    # log level
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_true",
        default=None,
        help="More verbose output",
    )
    log_group.add_argument(
        "-q",
        "--quiet",
        dest="verbosity",
        action="store_false",
        default=None,
        help="Less output",
    )

    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Show debug output (development)",
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

    # ipv4 asn mapping
    parser.add_argument(
        "--asn-map",
        type=Path,
        default=Path(FN_IPv4ASN_MAP),
        help="TSV file with mapping of IPv4 to ASN",
    )

    args = parser.parse_args(args)

    return args


# --------------------------------------------------------------------------


def cli_main(args=None):
    args = parse_args()

    setup_logging(verbose=args.verbosity)

    if args.debug:
        pprint(args.__dict__, stream=sys.stderr)

    from logalyzer.main import main

    main(files=args.files, ip2asn_file=args.asn_map, debug=args.debug)

    return 0


# --------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(cli_main())

# --------------------------------------------------------------------------
