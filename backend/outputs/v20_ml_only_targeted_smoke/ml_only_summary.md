# ML-only Suite Evaluation
- Suite: **targeted_next_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v20-attack-surface-ml95**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.3600** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **24/32** (75.00%)
- Full ML label+type accuracy: **23/32** (71.88%)
- Precision / Recall / F1: **0.6667 / 1.0000 / 0.8000**
- FP / FN: **8 / 0**
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'BLIND': 8, 'SECOND_ORDER': 4, 'IN_BAND': 11, 'NONE': 9}`

## Failures

- `targeted_next_debug_suite/java/018_NONE_safe_resultset_next_prepared.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/java/024_NONE_safe_resultset_param_reuse.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/java/029_NONE_safe_set_contains_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/javascript/013_NONE_safe_limit_offset_number_js.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9772`
- `targeted_next_debug_suite/javascript/016_NONE_safe_count_bool_js.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/javascript/022_NONE_safe_db_value_param_js.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9956`
- `targeted_next_debug_suite/php/020_NONE_safe_count_bool_php.php` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9999`
- `targeted_next_debug_suite/php/032_IN_BAND_vuln_array_map_but_raw_used.php` expected `VULNERABLE / IN_BAND` got `VULNERABLE / NONE` risk `0.6315`
- `targeted_next_debug_suite/python/003_NONE_safe_helper_pick_allowed_order_by.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9979`
