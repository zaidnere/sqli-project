# ML-only Suite Evaluation
- Total: **18**
- Threshold: **0.50**
- Binary ML accuracy: **13/18** (72.22%)
- Full ML label+type accuracy: **7/18** (38.89%)
- Expected attack distribution: `{'NONE': 6, 'IN_BAND': 4, 'BLIND': 4, 'SECOND_ORDER': 4}`
- ML attack distribution: `{'IN_BAND': 8, 'SECOND_ORDER': 5, 'NONE': 3, 'BLIND': 2}`

## Failures

- `realistic_long_sqli_suite/java/011_SAFE_SpringOrderRepository.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `realistic_long_sqli_suite/java/013_BLIND_LoginServiceStatement.java` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `realistic_long_sqli_suite/javascript/007_IN_BAND_express_template_where_vuln.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `realistic_long_sqli_suite/javascript/008_BLIND_feature_flag_check_vuln.js` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `0.9819`
- `realistic_long_sqli_suite/javascript/010_SAFE_reports_query_builder.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `realistic_long_sqli_suite/php/015_SAFE_PdoInventoryRepository.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9627`
- `realistic_long_sqli_suite/php/017_BLIND_FeatureFlagService.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9627`
- `realistic_long_sqli_suite/python/001_SAFE_flask_inventory_repository.py` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9507`
- `realistic_long_sqli_suite/python/002_IN_BAND_flask_customer_search_vulnerable.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `0.9507`
- `realistic_long_sqli_suite/python/003_BLIND_flask_permission_check.py` expected `VULNERABLE / BLIND` got `VULNERABLE / NONE` risk `1.0`
- `realistic_long_sqli_suite/python/005_SAFE_analytics_dashboard_complex.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
