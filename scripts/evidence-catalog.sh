#!/usr/bin/env bash
# evidence-catalog: the standard first pass over forensic inputs, once, before
# the agents start, into <sandbox>/catalog/ (harness-owned, read-only).
#
#   scripts/evidence-catalog.sh <sandbox> [--plan-only] [--recipes-from PACKDIR]...
#   scripts/evidence-catalog.sh --candidates <sandbox>
#
# The census (every input's coverage row) is the harness's; what an input is
# and how it is catalogued are the packs' recipes. The work is in
# evidence_catalog.py beside this script, which says how.
set -uo pipefail
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence_catalog.py" "$@"
