# ML-only Suite Evaluation
- Suite: **targeted_next_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **29/32** (90.62%)
- Full ML label+type accuracy: **29/32** (90.62%)
- Precision / Recall / F1: **0.8421 / 1.0000 / 0.9143**
- FP / FN: **3 / 0**
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'BLIND': 6, 'SECOND_ORDER': 3, 'NONE': 13, 'IN_BAND': 10}`

## Failures

- `targeted_next_debug_suite/java/018_NONE_safe_resultset_next_prepared.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `targeted_next_debug_suite/javascript/016_NONE_safe_count_bool_js.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9998`
- `targeted_next_debug_suite/php/020_NONE_safe_count_bool_php.php` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
