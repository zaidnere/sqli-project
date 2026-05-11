# ML-only Suite Evaluation
- Suite: **targeted_next_debug_suite.zip**
- Model version: **UNKNOWN**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5000** from `default_0.50`
- Total: **32**
- Binary ML accuracy: **27/32** (84.38%)
- Full ML label+type accuracy: **27/32** (84.38%)
- Precision / Recall / F1: **0.7619 / 1.0000 / 0.8649**
- FP / FN: **5 / 0**
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'BLIND': 6, 'SECOND_ORDER': 3, 'IN_BAND': 12, 'NONE': 11}`

## Failures

- `targeted_next_debug_suite/java/018_NONE_safe_resultset_next_prepared.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/java/024_NONE_safe_resultset_param_reuse.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `targeted_next_debug_suite/java/029_NONE_safe_set_contains_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `targeted_next_debug_suite/javascript/016_NONE_safe_count_bool_js.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9998`
- `targeted_next_debug_suite/php/020_NONE_safe_count_bool_php.php` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
