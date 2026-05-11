# ML-only Suite Evaluation
- Suite: **realistic_long_sqli_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `metadata.threshold`
- Total: **18**
- Binary ML accuracy: **15/18** (83.33%)
- Full ML label+type accuracy: **14/18** (77.78%)
- Precision / Recall / F1: **0.8462 / 0.9167 / 0.8800**
- FP / FN: **2 / 1**
- Expected attack distribution: `{'NONE': 6, 'IN_BAND': 4, 'BLIND': 4, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'NONE': 5, 'IN_BAND': 2, 'BLIND': 7, 'SECOND_ORDER': 4}`

## Failures

- `realistic_long_sqli_suite/php/016_IN_BAND_mysqli_customer_search.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.9218`
- `realistic_long_sqli_suite/python/001_SAFE_flask_inventory_repository.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `realistic_long_sqli_suite/python/002_IN_BAND_flask_customer_search_vulnerable.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9932`
- `realistic_long_sqli_suite/python/005_SAFE_analytics_dashboard_complex.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
