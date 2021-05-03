#!/usr/bin/env bash
#
# Run patatt from a git checkout.
#

REAL_SCRIPT=$(realpath -e ${BASH_SOURCE[0]})
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname ${REAL_SCRIPT})}"

exec env PYTHONPATH="${SCRIPT_TOP}" python3 "${SCRIPT_TOP}/patatt/__init__.py" "${@}"
