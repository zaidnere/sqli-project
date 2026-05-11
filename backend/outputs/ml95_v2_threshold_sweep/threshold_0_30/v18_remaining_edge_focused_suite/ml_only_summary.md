# ML-only Suite Evaluation
- Suite: **v18_remaining_edge_focused_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.3000** from `cli`
- Total: **28**
- Binary ML accuracy: **18/28** (64.29%)
- Full ML label+type accuracy: **16/28** (57.14%)
- Precision / Recall / F1: **0.6364 / 0.8750 / 0.7368**
- FP / FN: **8 / 2**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 8, 'SECOND_ORDER': 3, 'BLIND': 5}`
- ML attack distribution: `{'NONE': 6, 'SECOND_ORDER': 7, 'IN_BAND': 10, 'BLIND': 5}`

## Failures

- `v18_remaining_edge_focused_suite/javascript/002_SAFE_map_get_order_exact_var.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.4948`
- `v18_remaining_edge_focused_suite/javascript/004_SAFE_set_has_order_exact_var.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.6805`
- `v18_remaining_edge_focused_suite/javascript/005_IN_BAND_object_map_computed_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0001`
- `v18_remaining_edge_focused_suite/javascript/006_IN_BAND_set_has_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `0.307`
- `v18_remaining_edge_focused_suite/javascript/009_IN_BAND_direct_saved_segment_name_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `v18_remaining_edge_focused_suite/javascript/012_IN_BAND_sequelize_template_raw.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0659`
- `v18_remaining_edge_focused_suite/php/013_SAFE_array_whitelist_order_exact_var.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.4907`
- `v18_remaining_edge_focused_suite/php/014_SAFE_local_array_whitelist_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.4907`
- `v18_remaining_edge_focused_suite/php/015_SAFE_match_expression_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.4907`
- `v18_remaining_edge_focused_suite/php/016_SAFE_helper_pick_sort_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.8899`
- `v18_remaining_edge_focused_suite/php/026_SAFE_parameterized_count_bool.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.4907`
- `v18_remaining_edge_focused_suite/php/027_SAFE_static_pdo_query_no_input.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.4907`
