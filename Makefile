# SENTINEL.SQL — Developer Makefile
# Usage: make <target>
#
# Requires Python 3.12+ and Node 18+ in PATH.
# Run `make help` to list all targets.

BACKEND_DIR = backend
FRONTEND_DIR = frontend
VENV         = $(BACKEND_DIR)/venv
PYTHON       = $(VENV)/bin/python
PIP          = $(VENV)/bin/pip

.PHONY: help install install-backend install-frontend \
        dev dev-backend dev-frontend \
        export-colab validate-weights \
        lint clean

# ── Help ──────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  SENTINEL.SQL — available targets"
	@echo ""
	@echo "  Setup:"
	@echo "    make install          Install backend + frontend dependencies"
	@echo "    make install-backend  Install backend only"
	@echo "    make install-frontend Install frontend only"
	@echo ""
	@echo "  Development:"
	@echo "    make dev-backend      Start FastAPI server (http://127.0.0.1:8000)"
	@echo "    make dev-frontend     Start Vite dev server (http://localhost:5173)"
	@echo ""
	@echo "  AI Model:"
	@echo "    make export-colab     Export vocabulary + dataset for Colab training"
	@echo "    make validate-weights Validate sqli_model.npz after downloading from Colab"
	@echo ""
	@echo "  Other:"
	@echo "    make clean            Remove venv and node_modules"
	@echo ""

# ── Installation ──────────────────────────────────────────────────────────────

install: install-backend install-frontend
	@echo ""
	@echo "Installation complete."
	@echo "Copy backend/.env.example to backend/.env and set MONGODB_URL + JWT_SECRET_KEY"

install-backend:
	@echo "→ Creating virtual environment..."
	python3 -m venv $(VENV)
	@echo "→ Installing backend dependencies..."
	$(PIP) install --upgrade pip -q
	$(PIP) install -r $(BACKEND_DIR)/requirements.txt
	@echo "✓ Backend dependencies installed"

install-frontend:
	@echo "→ Installing frontend dependencies..."
	cd $(FRONTEND_DIR) && npm install
	@echo "✓ Frontend dependencies installed"

# ── Development servers ───────────────────────────────────────────────────────

dev-backend:
	@echo "→ Starting FastAPI backend on http://127.0.0.1:8000"
	cd $(BACKEND_DIR) && $(PYTHON) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

dev-frontend:
	@echo "→ Starting Vite frontend on http://localhost:5173"
	cd $(FRONTEND_DIR) && npm run dev

# ── AI Model workflow ─────────────────────────────────────────────────────────

export-colab:
	@echo "→ Exporting preprocessing artifacts for Colab training..."
	cd $(BACKEND_DIR) && $(PYTHON) scripts/export_for_colab.py
	@echo ""
	@echo "Next steps:"
	@echo "  1. Open sqli_colab_training.ipynb in Google Colab"
	@echo "  2. Upload backend/colab_export/vocabulary.json"
	@echo "  3. Upload backend/colab_export/training_data.npz"
	@echo "  4. Run all cells"
	@echo "  5. Download sqli_model.npz"
	@echo "  6. Run: make validate-weights"

validate-weights:
	@echo "→ Validating model weights..."
	cd $(BACKEND_DIR) && $(PYTHON) scripts/validate_weights.py

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	@echo "→ Removing backend virtual environment..."
	rm -rf $(VENV)
	@echo "→ Removing frontend node_modules..."
	rm -rf $(FRONTEND_DIR)/node_modules
	@echo "✓ Clean complete"
