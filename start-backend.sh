#!/bin/bash
# Start the SQLi Scanner backend server.
# Run from the project root: ./start-backend.sh

set -e

BACKEND_DIR="$(dirname "$0")/backend"
VENV="$BACKEND_DIR/venv"

# Use virtual environment if it exists, otherwise system Python
if [ -d "$VENV" ]; then
  PYTHON="$VENV/bin/python"
else
  PYTHON="python3"
fi

echo "SQLi Scanner — Backend"
echo "======================"

# Check .env
if [ ! -f "$BACKEND_DIR/.env" ]; then
  echo "WARNING: backend/.env not found."
  echo "Copy backend/.env.example to backend/.env and set MONGODB_URL + JWT_SECRET_KEY"
  echo ""
fi

# Validate model weights (informational — does not block startup)
echo "Checking model weights..."
$PYTHON "$BACKEND_DIR/scripts/validate_weights.py" || true
echo ""

echo "Starting FastAPI server on http://127.0.0.1:8000"
echo "Press Ctrl+C to stop."
echo ""

cd "$BACKEND_DIR"
$PYTHON -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
