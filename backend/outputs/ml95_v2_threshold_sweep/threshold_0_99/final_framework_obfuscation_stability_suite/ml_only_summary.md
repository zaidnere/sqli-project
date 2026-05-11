# ML-only Suite Evaluation
- Suite: **final_framework_obfuscation_stability_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9900** from `cli`
- Total: **64**
- Binary ML accuracy: **49/64** (76.56%)
- Full ML label+type accuracy: **43/64** (67.19%)
- Precision / Recall / F1: **0.7429 / 0.8125 / 0.7761**
- FP / FN: **9 / 6**
- Expected attack distribution: `{'NONE': 32, 'IN_BAND': 16, 'BLIND': 8, 'SECOND_ORDER': 8}`
- ML attack distribution: `{'IN_BAND': 15, 'NONE': 29, 'BLIND': 16, 'SECOND_ORDER': 4}`

## Failures

- `final_framework_obfuscation_stability_suite/java/033_SAFE_spring_jdbctemplate_params.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.995`
- `final_framework_obfuscation_stability_suite/java/036_IN_BAND_jpa_native_query_concat.java` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.9798`
- `final_framework_obfuscation_stability_suite/java/038_SECOND_ORDER_helper_return_fragment.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.9997`
- `final_framework_obfuscation_stability_suite/java/047_SAFE_only_comments.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/javascript/018_IN_BAND_sequelize_template_raw.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0001`
- `final_framework_obfuscation_stability_suite/javascript/020_IN_BAND_knex_raw_order.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0018`
- `final_framework_obfuscation_stability_suite/javascript/024_IN_BAND_exec_template_alias.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0266`
- `final_framework_obfuscation_stability_suite/javascript/026_SECOND_ORDER_huge_stored_query.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `final_framework_obfuscation_stability_suite/javascript/028_BLIND_feature_count_helper.js` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `final_framework_obfuscation_stability_suite/javascript/031_SAFE_only_comments.js` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `1.0`
- `final_framework_obfuscation_stability_suite/php/058_SECOND_ORDER_huge_stored_sql.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.4907`
- `final_framework_obfuscation_stability_suite/php/062_IN_BAND_multi_query_one_unsafe.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.4907`
- `final_framework_obfuscation_stability_suite/php/063_SAFE_only_comments.php` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9975`
- `final_framework_obfuscation_stability_suite/python/005_SAFE_sqlalchemy_text_params.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/007_SAFE_obfuscated_params_builder.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/008_IN_BAND_obfuscated_alias_execute.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/010_SECOND_ORDER_huge_stored_sql_late_sink.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `final_framework_obfuscation_stability_suite/python/011_SAFE_broken_looking_comments_hebrew.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/013_SAFE_multi_query_same_file.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/014_IN_BAND_multi_query_one_unsafe.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9932`
- `final_framework_obfuscation_stability_suite/python/016_SAFE_broken_syntax_no_crash.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9911`
