# ML-only Suite Evaluation
- Suite: **enterprise_realistic_sqli_final_suite.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.7000** from `cli`
- Total: **40**
- Binary ML accuracy: **30/40** (75.00%)
- Full ML label+type accuracy: **24/40** (60.00%)
- Precision / Recall / F1: **0.7812 / 0.8929 / 0.8333**
- FP / FN: **7 / 3**
- Expected attack distribution: `{'NONE': 12, 'IN_BAND': 9, 'BLIND': 8, 'SECOND_ORDER': 11}`
- ML attack distribution: `{'IN_BAND': 17, 'BLIND': 7, 'SECOND_ORDER': 8, 'NONE': 8}`

## Failures

- `enterprise_realistic_sqli_final_suite/java/021_SAFE_spring_invoice_repository.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `enterprise_realistic_sqli_final_suite/java/025_SAFE_set_contains_order.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `enterprise_realistic_sqli_final_suite/java/029_SAFE_db_value_bound_param.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9504`
- `enterprise_realistic_sqli_final_suite/java/030_SECOND_ORDER_config_condition.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `enterprise_realistic_sqli_final_suite/javascript/012_IN_BAND_template_customer_filter.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0`
- `enterprise_realistic_sqli_final_suite/javascript/016_IN_BAND_raw_order_decoy_set.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `0.9555`
- `enterprise_realistic_sqli_final_suite/javascript/019_SAFE_db_value_as_param.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9111`
- `enterprise_realistic_sqli_final_suite/javascript/020_IN_BAND_joined_ids_bulk_lookup.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0003`
- `enterprise_realistic_sqli_final_suite/php/034_SECOND_ORDER_saved_filter.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.9358`
- `enterprise_realistic_sqli_final_suite/php/038_SECOND_ORDER_stored_sql_report.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.0078`
- `enterprise_realistic_sqli_final_suite/python/001_SAFE_tenant_billing_repository.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9984`
- `enterprise_realistic_sqli_final_suite/python/003_BLIND_passwordless_login.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9984`
- `enterprise_realistic_sqli_final_suite/python/004_SECOND_ORDER_saved_widget_filter.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.9984`
- `enterprise_realistic_sqli_final_suite/python/005_SAFE_db_value_bound_parameter.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9984`
- `enterprise_realistic_sqli_final_suite/python/008_SECOND_ORDER_stored_sql_job_runner.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.9984`
- `enterprise_realistic_sqli_final_suite/python/009_SAFE_customer_search_decoys.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9984`
