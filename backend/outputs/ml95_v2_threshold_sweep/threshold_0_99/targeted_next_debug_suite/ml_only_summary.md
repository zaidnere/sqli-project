# ML-only Suite Evaluation
- Suite: **targeted_next_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9900** from `cli`
- Total: **32**
- Binary ML accuracy: **28/32** (87.50%)
- Full ML label+type accuracy: **28/32** (87.50%)
- Precision / Recall / F1: **0.8333 / 0.9375 / 0.8824**
- FP / FN: **3 / 1**
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'BLIND': 6, 'SECOND_ORDER': 3, 'NONE': 14, 'IN_BAND': 9}`

## Failures

- `targeted_next_debug_suite/java/018_NONE_safe_resultset_next_prepared.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/javascript/016_NONE_safe_count_bool_js.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9998`
- `targeted_next_debug_suite/php/020_NONE_safe_count_bool_php.php` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/php/032_IN_BAND_vuln_array_map_but_raw_used.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.9604`
