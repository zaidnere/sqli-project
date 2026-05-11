# ML-only Suite Evaluation
- Suite: **v18_provenance_overfit_guard_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **20**
- Binary ML accuracy: **13/20** (65.00%)
- Full ML label+type accuracy: **5/20** (25.00%)
- Precision / Recall / F1: **0.6500 / 1.0000 / 0.7879**
- FP / FN: **7 / 0**
- Expected attack distribution: `{'NONE': 7, 'IN_BAND': 8, 'SECOND_ORDER': 2, 'BLIND': 3}`
- ML attack distribution: `{'BLIND': 6, 'SECOND_ORDER': 2, 'NONE': 2, 'IN_BAND': 10}`

## Failures

- `v18_provenance_overfit_guard_suite/javascript/001_SAFE_object_map_alias_chain_order.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/002_IN_BAND_object_map_safe_then_raw_alias_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/003_SAFE_helper_allowlist_return_alias.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/004_IN_BAND_helper_called_but_request_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/006_IN_BAND_request_config_where_clause_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `v18_provenance_overfit_guard_suite/javascript/007_SECOND_ORDER_cache_config_order_clause.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/008_SAFE_config_value_as_bound_parameter.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `v18_provenance_overfit_guard_suite/javascript/009_BLIND_count_bool_return.js` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `v18_provenance_overfit_guard_suite/javascript/010_IN_BAND_count_returned_as_data.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / NONE` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/011_SAFE_property_array_alias_chain_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/013_SAFE_match_alias_chain_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/015_SAFE_helper_return_alias_chain_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/017_BLIND_count_alias_boolean_return_with_and.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/018_BLIND_count_alias_boolean_return_with_if.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/020_SAFE_pdo_parameterized_count_bool_guard.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
