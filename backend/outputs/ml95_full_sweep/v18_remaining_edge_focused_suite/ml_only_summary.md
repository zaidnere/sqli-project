# ML-only Suite Evaluation
- Suite: **v18_remaining_edge_focused_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **28**
- Binary ML accuracy: **16/28** (57.14%)
- Full ML label+type accuracy: **7/28** (25.00%)
- Precision / Recall / F1: **0.5714 / 1.0000 / 0.7273**
- FP / FN: **12 / 0**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 8, 'SECOND_ORDER': 3, 'BLIND': 5}`
- ML attack distribution: `{'BLIND': 9, 'SECOND_ORDER': 4, 'IN_BAND': 15}`

## Failures

- `v18_remaining_edge_focused_suite/javascript/001_SAFE_object_map_order_exact_var.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/002_SAFE_map_get_order_exact_var.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/003_SAFE_helper_pick_sort_order.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/004_SAFE_set_has_order_exact_var.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/005_IN_BAND_object_map_computed_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/006_IN_BAND_set_has_but_raw_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/009_IN_BAND_direct_saved_segment_name_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `v18_remaining_edge_focused_suite/javascript/010_SAFE_db_loaded_value_as_param_not_fragment.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/011_SAFE_sequelize_replacements_named.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/javascript/012_IN_BAND_sequelize_template_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_remaining_edge_focused_suite/php/013_SAFE_array_whitelist_order_exact_var.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/014_SAFE_local_array_whitelist_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/015_SAFE_match_expression_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/016_SAFE_helper_pick_sort_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/019_BLIND_count_alias_c_gt_zero.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/020_BLIND_fetch_assoc_row_exists.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/021_BLIND_num_rows_gt_zero.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/022_BLIND_helper_returns_bool.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/023_BLIND_feature_flag_enabled.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/026_SAFE_parameterized_count_bool.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_remaining_edge_focused_suite/php/027_SAFE_static_pdo_query_no_input.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
