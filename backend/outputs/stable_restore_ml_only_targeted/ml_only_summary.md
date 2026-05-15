# ML-only Suite Evaluation
- Suite: **targeted_next_debug_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-flow-generalization-v17**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5000** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **29/32** (90.62%)
- Full ML label+type accuracy: **29/32** (90.62%)
- Precision / Recall / F1: **0.8421 / 1.0000 / 0.9143**
- FP / FN: **3 / 0**
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'BLIND': 3, 'NONE': 13, 'SECOND_ORDER': 3, 'IN_BAND': 13}`

## Failures

- `targeted_next_debug_suite/java/029_NONE_safe_set_contains_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/php/031_NONE_safe_array_map_order_by.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9973`
- `targeted_next_debug_suite/python/005_NONE_safe_dict_map_table.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9965`
