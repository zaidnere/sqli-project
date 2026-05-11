# ML-only Suite Evaluation
- Suite: **root_cause_attack_type_diagnostic_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **23/32** (71.88%)
- Full ML label+type accuracy: **14/32** (43.75%)
- Precision / Recall / F1: **0.7000 / 1.0000 / 0.8235**
- FP / FN: **9 / 0**
- Expected attack distribution: `{'NONE': 11, 'IN_BAND': 10, 'SECOND_ORDER': 4, 'BLIND': 7}`
- ML attack distribution: `{'IN_BAND': 14, 'SECOND_ORDER': 6, 'BLIND': 7, 'NONE': 5}`

## Failures

- `root_cause_attack_type_diagnostic_suite/java/017_SAFE_named_parameter_jdbc_template.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9856`
- `root_cause_attack_type_diagnostic_suite/java/020_BLIND_time_based_sleep.java` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/java/022_SAFE_comments_string_no_sink.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/java/023_SAFE_db_loaded_value_param.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `root_cause_attack_type_diagnostic_suite/javascript/010_IN_BAND_direct_template_named_storedSegment.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/javascript/012_BLIND_feature_count_helper.js` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/javascript/013_BLIND_time_based_sleep_template.js` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/javascript/014_IN_BAND_direct_raw_ids_cached_name.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / NONE` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/javascript/015_SAFE_db_loaded_value_param.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `root_cause_attack_type_diagnostic_suite/javascript/016_SAFE_sequelize_replacements_decoy.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9495`
- `root_cause_attack_type_diagnostic_suite/php/030_SAFE_db_value_as_param.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/php/031_BLIND_time_based_sleep.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/python/001_SAFE_sql_like_string_no_sink.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9998`
- `root_cause_attack_type_diagnostic_suite/python/004_BLIND_time_based_pg_sleep.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/python/005_BLIND_count_helper.py` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/python/006_SAFE_db_loaded_value_param.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9507`
- `root_cause_attack_type_diagnostic_suite/python/007_IN_BAND_direct_raw_ids_join.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9507`
- `root_cause_attack_type_diagnostic_suite/python/008_SAFE_allowlist_decoy_stored_word.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9294`
