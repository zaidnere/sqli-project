# ML-only Suite Evaluation
- Suite: **adversarial_real_world_sqli_challenge_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `cli`
- Total: **32**
- Binary ML accuracy: **24/32** (75.00%)
- Full ML label+type accuracy: **22/32** (68.75%)
- Precision / Recall / F1: **0.7500 / 0.9000 / 0.8182**
- FP / FN: **6 / 2**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 8, 'BLIND': 8, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'SECOND_ORDER': 7, 'BLIND': 10, 'NONE': 8, 'IN_BAND': 7}`

## Failures

- `adversarial_real_world_sqli_challenge_suite/java/017_SAFE_named_jdbc_params_decoy.java` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9973`
- `adversarial_real_world_sqli_challenge_suite/java/018_IN_BAND_jdbc_concat_with_param_decoy.java` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/java/023_SAFE_comments_only.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/javascript/010_IN_BAND_replacements_exist_template_used.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0031`
- `adversarial_real_world_sqli_challenge_suite/javascript/014_IN_BAND_alias_bind_raw_table.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `0.9848`
- `adversarial_real_world_sqli_challenge_suite/javascript/015_SAFE_comments_only.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/031_SAFE_comments_only.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9672`
- `adversarial_real_world_sqli_challenge_suite/php/032_BLIND_time_based_raw.php` expected `VULNERABLE / BLIND` got `SAFE / NONE` risk `0.4907`
- `adversarial_real_world_sqli_challenge_suite/python/005_SAFE_db_value_as_param_long_gap.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `adversarial_real_world_sqli_challenge_suite/python/007_SAFE_sql_strings_comments_only.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9654`
