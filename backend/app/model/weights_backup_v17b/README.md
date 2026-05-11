# Model Weights Directory

Place the trained model file here:

```
backend/app/model/weights/sqli_model.npz
```

## How to train and deploy the model

1. **Generate Colab data** — run from `backend/`:
   ```bash
   python scripts/export_for_colab.py
   ```
   This creates `backend/colab_export/vocabulary.json` and `backend/colab_export/training_data.npz`.

2. **Train in Google Colab** — open `sqli_colab_training.ipynb` (project root):
   - Upload `vocabulary.json` and `training_data.npz` to the Colab session
   - Run all cells
   - Download `sqli_model.npz` when training is complete

3. **Deploy weights** — place the downloaded file here:
   ```
   backend/app/model/weights/sqli_model.npz
   ```

4. **Restart backend** — the model loads automatically on startup.
   All scans will now return a `detection` result with `riskScore`, `label`, and `recommendation`.

## Status check

Call `GET /api/scans/model-status` (no auth required) to verify the model is loaded:

```json
{
  "modelLoaded": true,
  "message": "Detection model is ready.",
  "weightsPath": "/path/to/sqli_model.npz"
}
```

## Git note

`sqli_model.npz` is excluded from version control via `.gitignore`.
The `.gitkeep` file ensures this directory is tracked by git.
