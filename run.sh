#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
PYTHON="${VENV_DIR}/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
    python3 -m venv "${VENV_DIR}"
fi

"${PYTHON}" -m pip install -r "${PROJECT_DIR}/requirements.txt"
exec "${PYTHON}" "${PROJECT_DIR}/manage.py" start_demo "$@"