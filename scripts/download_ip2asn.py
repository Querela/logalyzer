# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2.32.5",
# ]
# ///

import gzip
import json
import logging
import os.path
import shutil
import sys
from functools import lru_cache
from pprint import pprint
from typing import Dict, Optional, TypedDict

import requests

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(
    __name__
    if __name__ != "__main__"
    else os.path.splitext(os.path.basename(__file__))[0]
)

# --------------------------------------------------------------------------

base = os.path.dirname(__file__)
relbase = os.getcwd()

DN_BASE = os.path.relpath(os.path.join(base, ".."), relbase)
FN_IPv4ASN_MAP = os.path.join(DN_BASE, "ip2asn-v4.tsv")

FN_IPv4ASN_MAP_ARCHIVE = os.path.join(DN_BASE, "ip2asn-v4.tsv.gz")
FN_IPv4ASN_MAP_ARCHIVE_META = os.path.join(DN_BASE, "ip2asn-v4.tsv.gz.meta")

URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

CHUNK_SIZE = 10 * 1024
CACHE_INFO_KEYS = ["last-modified", "etag", "expires"]

# --------------------------------------------------------------------------


CacheInfo = TypedDict(
    "CacheInfo",
    {
        "last-modified": Optional[str],
        "etag": Optional[str],
        "expires": Optional[str],
    },
)


@lru_cache(maxsize=1)
def load_cache_info():
    try:
        with open(FN_IPv4ASN_MAP_ARCHIVE_META, "rb") as fp:
            cache_info: CacheInfo = json.load(fp)
            return cache_info
    except FileNotFoundError as ex:
        LOGGER.warning(f"Cache info file '{FN_IPv4ASN_MAP_ARCHIVE_META}' not found.")
        return None


@lru_cache(maxsize=1)
def cache_headers() -> Dict[str, str]:
    cache_info = load_cache_info()
    if cache_info is None:
        return dict()

    headers = {
        "If-None-Match": cache_info.get("etag", None),
        "If-Modified-Since": cache_info.get("last-modified", None),
    }
    headers = {k: v for k, v in headers.items() if v is not None}
    LOGGER.debug(f"Cache headers: {headers!r}")

    return headers


def require_update():
    if not os.path.isfile(FN_IPv4ASN_MAP):
        LOGGER.warning(f"No data file '{FN_IPv4ASN_MAP}' found!")
        return True

    # or not os.path.isfile(FN_IPv4ASN_MAP_ARCHIVE)
    # f"or archive data file '{FN_IPv4ASN_MAP_ARCHIVE}'"

    if load_cache_info() is None:
        return True

    return False


def check_has_newer():
    headers = cache_headers()
    if not headers:
        return True

    with requests.head(URL, headers=headers, allow_redirects=True) as resp:
        if resp.status_code == requests.codes["not_modified"]:
            return False

    return True


def download_data():
    show_progress = LOGGER.isEnabledFor(logging.DEBUG)
    LOGGER.info(f"Download '{URL}' ...")
    with requests.get(URL, allow_redirects=True, stream=True) as resp:
        LOGGER.debug(f"Response status code: {resp.status_code!r}")

        cache_info: CacheInfo = {
            k: v for k, v in resp.headers.items() if k in CACHE_INFO_KEYS
        }
        LOGGER.debug(f"New cache info: {cache_info!r}")

        with open(FN_IPv4ASN_MAP_ARCHIVE, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                fp.write(chunk)
                if show_progress:
                    print(f"\rDownloaded {fp.tell():,d} bytes", end="", file=sys.stderr)
            if show_progress:
                print()
        LOGGER.info(f"Wrote '{FN_IPv4ASN_MAP_ARCHIVE}'.")

        with open(FN_IPv4ASN_MAP_ARCHIVE_META, "w") as fp:
            json.dump(cache_info, fp)
        LOGGER.info(f"Wrote '{FN_IPv4ASN_MAP_ARCHIVE_META}'.")

    return True


def decompress_data():
    with gzip.open(FN_IPv4ASN_MAP_ARCHIVE, "rb") as fp_in:
        with open(FN_IPv4ASN_MAP, "wb") as fp_out:
            shutil.copyfileobj(fp_in, fp_out)

    os.unlink(FN_IPv4ASN_MAP_ARCHIVE)

    LOGGER.info(f"Extracted '{FN_IPv4ASN_MAP_ARCHIVE}' to '{FN_IPv4ASN_MAP}'.")


def download_ip2asn_data(force_update: bool = False):
    do_update = force_update

    # check if data files are missing
    if require_update():
        do_update = True

    # check if newer version is available
    if not do_update:
        if check_has_newer():
            do_update = True

    if do_update:
        download_data()
        decompress_data()
    else:
        LOGGER.info("No update required!")

    return 0


# --------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        format="[%(levelname)s] %(name)s: %(message)s", level=logging.DEBUG
    )
    logging.getLogger("urllib3").setLevel(logging.INFO)

    sys.exit(download_ip2asn_data())
