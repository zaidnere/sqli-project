# ML-only Suite Evaluation
- Suite: **mega_sqli_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.6000** from `cli`
- Total: **40**
- Binary ML accuracy: **37/40** (92.50%)
- Full ML label+type accuracy: **36/40** (90.00%)
- Precision / Recall / F1: **0.8929 / 1.0000 / 0.9434**
- FP / FN: **3 / 0**
- Expected attack distribution: `{'IN_BAND': 15, 'NONE': 15, 'BLIND': 5, 'SECOND_ORDER': 5}`
- ML attack distribution: `{'IN_BAND': 16, 'BLIND': 6, 'SECOND_ORDER': 6, 'NONE': 12}`

## Failures

- `mega_sqli_debug_suite/java/030_NONE_safe_prepared_statement.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `mega_sqli_debug_suite/java/033_NONE_safe_whitelist_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `mega_sqli_debug_suite/php/040_IN_BAND_vuln_raw_order_by.php` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `mega_sqli_debug_suite/python/010_NONE_safe_parameterized_boolean.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9994`
