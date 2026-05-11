# ML-only Suite Evaluation
- Suite: **known_good_sqli_detection_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **40**
- Binary ML accuracy: **25/40** (62.50%)
- Full ML label+type accuracy: **16/40** (40.00%)
- Precision / Recall / F1: **0.6154 / 1.0000 / 0.7619**
- FP / FN: **15 / 0**
- Expected attack distribution: `{'NONE': 16, 'IN_BAND': 12, 'BLIND': 8, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'BLIND': 13, 'IN_BAND': 19, 'NONE': 5, 'SECOND_ORDER': 3}`

## Failures

- `known_good_sqli_detection_suite/java/021_SAFE_prepared_statement.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `known_good_sqli_detection_suite/java/022_SAFE_set_contains_order.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `known_good_sqli_detection_suite/java/028_SECOND_ORDER_getstring_fragment.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/java/029_SAFE_db_value_as_param.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `known_good_sqli_detection_suite/java/030_SAFE_comments_only.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/javascript/011_SAFE_db_all_params.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `known_good_sqli_detection_suite/javascript/012_SAFE_allowlisted_order.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `known_good_sqli_detection_suite/javascript/014_IN_BAND_raw_order.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `known_good_sqli_detection_suite/javascript/016_BLIND_session_verifier.js` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `known_good_sqli_detection_suite/javascript/017_BLIND_count_bool.js` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `known_good_sqli_detection_suite/javascript/019_SAFE_db_value_as_param.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `known_good_sqli_detection_suite/javascript/020_SAFE_comments_only.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `known_good_sqli_detection_suite/php/031_SAFE_pdo_prepare_execute.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9984`
- `known_good_sqli_detection_suite/php/032_SAFE_array_whitelist_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9643`
- `known_good_sqli_detection_suite/php/036_BLIND_login_raw.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9984`
- `known_good_sqli_detection_suite/php/037_BLIND_count_bool.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9984`
- `known_good_sqli_detection_suite/php/039_SAFE_db_value_as_param.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9984`
- `known_good_sqli_detection_suite/python/001_SAFE_parameterized_execute.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9507`
- `known_good_sqli_detection_suite/python/002_SAFE_allowlisted_order_by.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9294`
- `known_good_sqli_detection_suite/python/004_IN_BAND_raw_order_by.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9507`
- `known_good_sqli_detection_suite/python/006_BLIND_login_raw.py` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `0.9999`
- `known_good_sqli_detection_suite/python/007_BLIND_count_gt_zero.py` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `known_good_sqli_detection_suite/python/009_SAFE_db_loaded_value_as_param.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9507`
- `known_good_sqli_detection_suite/python/010_SAFE_static_executescript.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
