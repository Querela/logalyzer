import os.path


# --------------------------------------------------------------------------

base = os.path.dirname(__file__)
relbase = os.getcwd()

DN_BASE = os.path.relpath(os.path.join(base, "../.."), relbase)
FN_IPv4ASN_MAP = os.path.join(DN_BASE, "ip2asn-v4.tsv")

# --------------------------------------------------------------------------
