# SQLi Test Suite Results

- Total: **40**
- Passed: **40**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_tenant_billing_repository.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `python/002_IN_BAND_support_ticket_search.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 3 | `python/003_BLIND_passwordless_login.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 4 | `python/004_SECOND_ORDER_saved_widget_filter.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 5 | `python/005_SAFE_db_value_bound_parameter.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 6 | `python/006_IN_BAND_raw_table_selector_decoy.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 7 | `python/007_BLIND_feature_gate_count.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 8 | `python/008_SECOND_ORDER_stored_sql_job_runner.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 9 | `python/009_SAFE_customer_search_decoys.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 10 | `python/010_SECOND_ORDER_cached_order_expression.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 11 | `javascript/011_SAFE_express_billing_repository.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 12 | `javascript/012_IN_BAND_template_customer_filter.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 13 | `javascript/013_BLIND_session_verifier.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 14 | `javascript/014_SECOND_ORDER_saved_segment_runner.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 15 | `javascript/015_SAFE_report_params_variable.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 16 | `javascript/016_IN_BAND_raw_order_decoy_set.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 17 | `javascript/017_BLIND_feature_gate.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 18 | `javascript/018_SECOND_ORDER_stored_query_executor.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 19 | `javascript/019_SAFE_db_value_as_param.js` | SAFE / NONE | SAFE / NONE | 0.067 | ✅ |
| 20 | `javascript/020_IN_BAND_joined_ids_bulk_lookup.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 21 | `java/021_SAFE_spring_invoice_repository.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 22 | `java/022_IN_BAND_legacy_customer_statement.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9531 | ✅ |
| 23 | `java/023_BLIND_login_statement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 24 | `java/024_SECOND_ORDER_audit_export_fragment.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 25 | `java/025_SAFE_set_contains_order.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 26 | `java/026_IN_BAND_raw_order_decoy.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 27 | `java/027_BLIND_permission_count.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 28 | `java/028_SECOND_ORDER_stored_query_runner.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 29 | `java/029_SAFE_db_value_bound_param.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 30 | `java/030_SECOND_ORDER_config_condition.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9989 | ✅ |
| 31 | `php/031_SAFE_pdo_order_repository.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 32 | `php/032_IN_BAND_mysqli_customer_search.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 33 | `php/033_BLIND_login_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 34 | `php/034_SECOND_ORDER_saved_filter.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 35 | `php/035_SAFE_placeholder_in_list.php` | SAFE / NONE | SAFE / NONE | 0.0003 | ✅ |
| 36 | `php/036_IN_BAND_raw_ids_implode.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 37 | `php/037_BLIND_permission_exists.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 38 | `php/038_SECOND_ORDER_stored_sql_report.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 39 | `php/039_SAFE_db_value_as_param.php` | SAFE / NONE | SAFE / NONE | 0.0003 | ✅ |
| 40 | `php/040_SECOND_ORDER_config_order_clause.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |