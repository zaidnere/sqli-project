# ML-only Suite Evaluation
- Suite: **hard_mixed_sqli_challenge_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `cli`
- Total: **80**
- Binary ML accuracy: **77/80** (96.25%)
- Full ML label+type accuracy: **72/80** (90.00%)
- Precision / Recall / F1: **0.9831 / 0.9667 / 0.9748**
- FP / FN: **1 / 2**
- Expected attack distribution: `{'NONE': 20, 'IN_BAND': 20, 'BLIND': 20, 'SECOND_ORDER': 20}`
- ML attack distribution: `{'NONE': 21, 'BLIND': 21, 'IN_BAND': 24, 'SECOND_ORDER': 14}`

## Failures

- `hard_mixed_sqli_challenge_suite/java/042_SAFE_resultset_next_prepared_bool.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9995`
- `hard_mixed_sqli_challenge_suite/java/060_SECOND_ORDER_cached_config_where.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `hard_mixed_sqli_challenge_suite/javascript/037_SECOND_ORDER_cached_fragment.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `hard_mixed_sqli_challenge_suite/javascript/039_SECOND_ORDER_stored_query.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `hard_mixed_sqli_challenge_suite/php/068_IN_BAND_raw_ids_implode.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0`
- `hard_mixed_sqli_challenge_suite/php/079_SECOND_ORDER_stored_sql_run.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.5728`
- `hard_mixed_sqli_challenge_suite/python/017_SECOND_ORDER_cached_row_fragment.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `hard_mixed_sqli_challenge_suite/python/019_SECOND_ORDER_stored_script_executescript.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
