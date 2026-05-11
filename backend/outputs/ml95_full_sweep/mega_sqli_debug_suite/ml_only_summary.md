# ML-only Suite Evaluation
- Suite: **mega_sqli_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **40**
- Binary ML accuracy: **30/40** (75.00%)
- Full ML label+type accuracy: **25/40** (62.50%)
- Precision / Recall / F1: **0.7273 / 0.9600 / 0.8276**
- FP / FN: **9 / 1**
- Expected attack distribution: `{'IN_BAND': 15, 'NONE': 15, 'BLIND': 5, 'SECOND_ORDER': 5}`
- ML attack distribution: `{'IN_BAND': 21, 'SECOND_ORDER': 6, 'BLIND': 6, 'NONE': 7}`

## Failures

- `mega_sqli_debug_suite/java/030_NONE_safe_prepared_statement.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/java/031_BLIND_vuln_boolean_login.java` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/java/033_NONE_safe_whitelist_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/javascript/022_NONE_safe_parameterized_query.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9992`
- `mega_sqli_debug_suite/javascript/025_NONE_safe_whitelist_order_by.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/javascript/026_IN_BAND_vuln_raw_order_by.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `mega_sqli_debug_suite/php/037_BLIND_vuln_count_bool.php` expected `VULNERABLE / BLIND` got `SAFE / NONE` risk `0.001`
- `mega_sqli_debug_suite/php/039_NONE_safe_whitelist_order_by.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/python/001_NONE_safe_direct_whitelist_order_by.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/python/006_NONE_safe_limit_offset_int_bounds.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/python/014_NONE_safe_static_executescript.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/python/015_IN_BAND_vuln_executescript_fstring.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `1.0`
- `mega_sqli_debug_suite/python/016_IN_BAND_vuln_replace_sanitized_like.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `1.0`
- `mega_sqli_debug_suite/python/019_NONE_safe_dict_map_table.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `mega_sqli_debug_suite/python/020_IN_BAND_vuln_dynamic_table_raw.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `1.0`
