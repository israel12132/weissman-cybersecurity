#!/usr/bin/env bash
# Weissman-cybersecurity: install all dependencies (no conflicts, latest compatible)
# Usage: ./install_deps.sh   OR:  bash install_deps.sh

set -e
cd "$(dirname "$0")"

echo "=== Weissman-cybersecurity: Installing dependencies ==="
if [ ! -d "venv" ]; then
    echo "Creating venv..."
    python3 -m venv venv
fi
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip -q

echo "Installing from requirements.txt (latest compatible, conflict-free)..."
pip install -r requirements.txt --upgrade

echo "Checking for dependency conflicts..."
pip check
if [ $? -ne 0 ]; then
    echo "ERROR: pip check found conflicts. Fix requirements or constraints."
    exit 1
fi

echo "Verifying core library imports (orchestration is Rust; no FastAPI/Celery)..."
python3 -c "
from src.pdf_export import generate_report_pdf
from src.database import get_db
from src.correlation import correlate_findings_from_db
from src.webhooks import push_findings_to_webhooks
from openpyxl import Workbook
print('  OK: all imports succeeded')
"

echo ""
echo "=== SUCCESS: All libraries installed and compatible. ==="
echo "Run the bot with:  ./start_weissman.sh"
