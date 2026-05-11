# ML-only Suite Evaluation
- Suite: **known_good_sqli_detection_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `cli`
- Total: **40**
- Binary ML accuracy: **30/40** (75.00%)
- Full ML label+type accuracy: **27/40** (67.50%)
- Precision / Recall / F1: **0.7059 / 1.0000 / 0.8276**
- FP / FN: **10 / 0**
- Expected attack distribution: `{'NONE': 16, 'IN_BAND': 12, 'BLIND': 8, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'IN_BAND': 17, 'SECOND_ORDER': 5, 'BLIND': 12, 'NONE': 6}`

## Failures

- `known_good_sqli_detection_suite/java/021_SAFE_prepared_statement.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `known_good_sqli_detection_suite/java/022_SAFE_set_contains_order.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `known_good_sqli_detection_suite/java/024_IN_BAND_raw_order.java` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `known_good_sqli_detection_suite/java/028_SECOND_ORDER_getstring_fragment.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/java/029_SAFE_db_value_as_param.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `known_good_sqli_detection_suite/java/030_SAFE_comments_only.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9988`
- `known_good_sqli_detection_suite/javascript/014_IN_BAND_raw_order.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `0.9998`
- `known_good_sqli_detection_suite/javascript/020_SAFE_comments_only.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/php/040_SAFE_comments_only.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/python/001_SAFE_parameterized_execute.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `known_good_sqli_detection_suite/python/002_SAFE_allowlisted_order_by.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.8522`
- `known_good_sqli_detection_suite/python/009_SAFE_db_loaded_value_as_param.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `known_good_sqli_detection_suite/python/010_SAFE_static_executescript.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
