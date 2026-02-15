# Logalyzer

Analyzes Apache log files for excessive requests and create various usage statistics.

## Installation

Clone the repo from Github:

```bash
git clone https://github.com/Querela/logalyzer.git
cd logalyzer
```

The `uv` command should install everything automatically when trying to run the `logalyzer` but you can probably try `uv sync`, too.

Before the first run, prepare runtime data (IPv4 ASN lookup):

```bash
uv run scripts/download_ip2asn.py
```

The command can also be run to update the data if a newer version is detected.

## Run Analyses

```bash
# show help
uv run logalyzer -h

# run for all files in any subdirectory with '.log' in its name
uv run logalyzer -i '**/*.log*'

# run with debug mode for a single file
uv run logalyzer --debug -i 'data/access.log.2026-01-01.gz'
```

## Extra data

- IPv4 ASN lookup - https://iptoasn.com/:
  - https://iptoasn.com/data/ip2asn-v4.tsv.gz
  - Run `uv run scripts/download_ip2asn.py` to download/update
