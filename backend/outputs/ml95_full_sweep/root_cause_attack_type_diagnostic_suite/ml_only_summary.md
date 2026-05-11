# ML-only Suite Evaluation
- Suite: **root_cause_attack_type_diagnostic_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9600** from `metadata.threshold`
- Total: **32**
- Binary ML accuracy: **26/32** (81.25%)
- Full ML label+type accuracy: **22/32** (68.75%)
- Precision / Recall / F1: **0.8000 / 0.9524 / 0.8696**
- FP / FN: **5 / 1**
- Expected attack distribution: `{'NONE': 11, 'IN_BAND': 10, 'SECOND_ORDER': 4, 'BLIND': 7}`
- ML attack distribution: `{'SECOND_ORDER': 6, 'BLIND': 7, 'NONE': 7, 'IN_BAND': 12}`

## Failures

- `root_cause_attack_type_diagnostic_suite/java/017_SAFE_named_parameter_jdbc_template.java` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9973`
- `root_cause_attack_type_diagnostic_suite/java/018_IN_BAND_named_parameter_concat_email.java` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `0.9973`
- `root_cause_attack_type_diagnostic_suite/java/022_SAFE_comments_string_no_sink.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9988`
- `root_cause_attack_type_diagnostic_suite/javascript/009_SAFE_sql_like_string_no_sink.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9989`
- `root_cause_attack_type_diagnostic_suite/javascript/012_BLIND_feature_count_helper.js` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/php/025_SAFE_comment_string_no_sink.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/php/031_BLIND_time_based_sleep.php` expected `VULNERABLE / BLIND` got `SAFE / NONE` risk `0.4907`
- `root_cause_attack_type_diagnostic_suite/python/005_BLIND_count_helper.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `root_cause_attack_type_diagnostic_suite/python/006_SAFE_db_loaded_value_param.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `root_cause_attack_type_diagnostic_suite/python/007_IN_BAND_direct_raw_ids_join.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9932`
