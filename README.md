# Logalyzer

Analyzes Apache log files for excessive requests and create various usage statistics.

## Installation

`uv run` might install everything automatically?
Otherwise try `uv sync`.

## Run

```bash
# show help
uv run logalyzer -h

# run for all files in any subdirectory with '.log' in its name
uv run logalyzer -i '**/*.log*'

# run with debug mode for a single file
uv run logalyzer --debug -i 'data/access.log.2026-01-01.gz'
```

## Extra data

- IPv4 ASN lookup:
  - https://iptoasn.com/data/ip2asn-v4.tsv.gz
