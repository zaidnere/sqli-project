# SQLi Test Suite Results

- Total: **18**
- Passed: **18**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_flask_inventory_repository.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `python/002_IN_BAND_flask_customer_search_vulnerable.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 3 | `python/003_BLIND_flask_permission_check.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9987 | ✅ |
| 4 | `python/004_SECOND_ORDER_saved_report_runner.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 5 | `python/005_SAFE_analytics_dashboard_complex.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 6 | `javascript/006_SAFE_express_orders_repository.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 7 | `javascript/007_IN_BAND_express_template_where_vuln.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 8 | `javascript/008_BLIND_feature_flag_check_vuln.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 9 | `javascript/009_SECOND_ORDER_saved_segment_runner.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 10 | `javascript/010_SAFE_reports_query_builder.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 11 | `java/011_SAFE_SpringOrderRepository.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 12 | `java/012_IN_BAND_legacyStatementSearch.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 13 | `java/013_BLIND_LoginServiceStatement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 14 | `java/014_SECOND_ORDER_AuditArchiveService.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 15 | `php/015_SAFE_PdoInventoryRepository.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 16 | `php/016_IN_BAND_mysqli_customer_search.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9218 | ✅ |
| 17 | `php/017_BLIND_FeatureFlagService.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 18 | `php/018_SECOND_ORDER_ProfileAudit.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |