# ML-only Suite Evaluation
- Suite: **v18_remaining_edge_focused_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.7000** from `cli`
- Total: **28**
- Binary ML accuracy: **24/28** (85.71%)
- Full ML label+type accuracy: **23/28** (82.14%)
- Precision / Recall / F1: **0.9286 / 0.8125 / 0.8667**
- FP / FN: **1 / 3**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 8, 'SECOND_ORDER': 3, 'BLIND': 5}`
- ML attack distribution: `{'NONE': 14, 'SECOND_ORDER': 4, 'IN_BAND': 5, 'BLIND': 5}`

## Failures

- `v18_remaining_edge_focused_suite/javascript/005_IN_BAND_object_map_computed_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0001`
- `v18_remaining_edge_focused_suite/javascript/006_IN_BAND_set_has_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.307`
- `v18_remaining_edge_focused_suite/javascript/009_IN_BAND_direct_saved_segment_name_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `v18_remaining_edge_focused_suite/javascript/012_IN_BAND_sequelize_template_raw.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0659`
- `v18_remaining_edge_focused_suite/php/016_SAFE_helper_pick_sort_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.8899`
