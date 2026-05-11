# ML-only Suite Evaluation
- Suite: **stable_expected_detection_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9900** from `cli`
- Total: **40**
- Binary ML accuracy: **35/40** (87.50%)
- Full ML label+type accuracy: **30/40** (75.00%)
- Precision / Recall / F1: **0.8400 / 0.9545 / 0.8936**
- FP / FN: **4 / 1**
- Expected attack distribution: `{'NONE': 18, 'IN_BAND': 6, 'BLIND': 8, 'SECOND_ORDER': 8}`
- ML attack distribution: `{'NONE': 15, 'IN_BAND': 7, 'SECOND_ORDER': 6, 'BLIND': 12}`

## Failures

- `stable_expected_detection_suite/java/024_IN_BAND_statement_update_concat.java` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `stable_expected_detection_suite/java/027_SECOND_ORDER_saved_where_clause.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `stable_expected_detection_suite/javascript/014_IN_BAND_concat_update_status.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `stable_expected_detection_suite/javascript/018_SECOND_ORDER_stored_query_runner.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.9999`
- `stable_expected_detection_suite/php/037_SECOND_ORDER_stored_query.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.4907`
- `stable_expected_detection_suite/python/001_SAFE_basic_parameterized_lookup.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `stable_expected_detection_suite/python/002_SAFE_insert_parameterized.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `stable_expected_detection_suite/python/003_SAFE_update_parameterized.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `stable_expected_detection_suite/python/009_SECOND_ORDER_stored_full_query.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `stable_expected_detection_suite/python/010_SAFE_db_loaded_value_as_param.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
