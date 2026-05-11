# ML-only Suite Evaluation
- Suite: **v18_provenance_overfit_guard_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `metadata.threshold`
- Total: **20**
- Binary ML accuracy: **15/20** (75.00%)
- Full ML label+type accuracy: **14/20** (70.00%)
- Precision / Recall / F1: **0.8333 / 0.7692 / 0.8000**
- FP / FN: **2 / 3**
- Expected attack distribution: `{'NONE': 7, 'IN_BAND': 8, 'SECOND_ORDER': 2, 'BLIND': 3}`
- ML attack distribution: `{'NONE': 8, 'SECOND_ORDER': 3, 'BLIND': 3, 'IN_BAND': 6}`

## Failures

- `v18_provenance_overfit_guard_suite/javascript/002_IN_BAND_object_map_safe_then_raw_alias_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0005`
- `v18_provenance_overfit_guard_suite/javascript/004_IN_BAND_helper_called_but_request_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0001`
- `v18_provenance_overfit_guard_suite/javascript/006_IN_BAND_request_config_where_clause_raw.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `v18_provenance_overfit_guard_suite/php/011_SAFE_property_array_alias_chain_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9991`
- `v18_provenance_overfit_guard_suite/php/014_IN_BAND_match_exists_but_raw_used.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.7127`
- `v18_provenance_overfit_guard_suite/php/015_SAFE_helper_return_alias_chain_order.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9662`
