# ML-only Suite Evaluation
- Suite: **adversarial_real_world_sqli_challenge_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **20/32** (62.50%)
- Full ML label+type accuracy: **8/32** (25.00%)
- Precision / Recall / F1: **0.6250 / 1.0000 / 0.7692**
- FP / FN: **12 / 0**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 8, 'BLIND': 8, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'IN_BAND': 15, 'NONE': 1, 'BLIND': 11, 'SECOND_ORDER': 5}`

## Failures

- `adversarial_real_world_sqli_challenge_suite/java/017_SAFE_named_jdbc_params_decoy.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9856`
- `adversarial_real_world_sqli_challenge_suite/java/019_BLIND_exists_helper.java` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/java/020_SECOND_ORDER_stored_sql_helper.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/java/021_SAFE_rs_value_bound_param.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `adversarial_real_world_sqli_challenge_suite/java/023_SAFE_comments_only.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9294`
- `adversarial_real_world_sqli_challenge_suite/java/024_BLIND_time_based_statement.java` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/javascript/009_SAFE_sequelize_replacements_decoy.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `adversarial_real_world_sqli_challenge_suite/javascript/010_IN_BAND_replacements_exist_template_used.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `adversarial_real_world_sqli_challenge_suite/javascript/013_SAFE_sqlite_params_spread_decoy.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `adversarial_real_world_sqli_challenge_suite/javascript/014_IN_BAND_alias_bind_raw_table.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9495`
- `adversarial_real_world_sqli_challenge_suite/javascript/015_SAFE_comments_only.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9485`
- `adversarial_real_world_sqli_challenge_suite/javascript/016_BLIND_time_based_template.js` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/025_SAFE_pdo_allowlist_clamp_decoys.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/027_BLIND_fetch_assoc_helper.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/029_SAFE_db_value_bound_param.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/031_SAFE_comments_only.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/php/032_BLIND_time_based_raw.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/python/001_SAFE_nested_allowlist_decoys.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9294`
- `adversarial_real_world_sqli_challenge_suite/python/002_IN_BAND_helper_returns_raw_order.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/python/003_BLIND_nested_exists_helper.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `adversarial_real_world_sqli_challenge_suite/python/005_SAFE_db_value_as_param_long_gap.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9507`
- `adversarial_real_world_sqli_challenge_suite/python/006_IN_BAND_execute_alias.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9507`
- `adversarial_real_world_sqli_challenge_suite/python/007_SAFE_sql_strings_comments_only.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9993`
- `adversarial_real_world_sqli_challenge_suite/python/008_BLIND_time_based.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
