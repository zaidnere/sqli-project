# SQLi Test Suite Results

- Total: **18**
- Passed: **14**
- Failed: **4**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_flask_inventory_repository.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 2 | `python/002_IN_BAND_flask_customer_search_vulnerable.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 3 | `python/003_BLIND_flask_permission_check.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 4 | `python/004_SECOND_ORDER_saved_report_runner.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 5 | `python/005_SAFE_analytics_dashboard_complex.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 6 | `javascript/006_SAFE_express_orders_repository.js` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 7 | `javascript/007_IN_BAND_express_template_where_vuln.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 8 | `javascript/008_BLIND_feature_flag_check_vuln.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 9 | `javascript/009_SECOND_ORDER_saved_segment_runner.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 10 | `javascript/010_SAFE_reports_query_builder.js` | SAFE / NONE | VULNERABLE / BLIND | 0.8759 | ❌ |
| 11 | `java/011_SAFE_SpringOrderRepository.java` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9295 | ❌ |
| 12 | `java/012_IN_BAND_legacyStatementSearch.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9295 | ✅ |
| 13 | `java/013_BLIND_LoginServiceStatement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9295 | ✅ |
| 14 | `java/014_SECOND_ORDER_AuditArchiveService.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9295 | ✅ |
| 15 | `php/015_SAFE_PdoInventoryRepository.php` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 16 | `php/016_IN_BAND_mysqli_customer_search.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 17 | `php/017_BLIND_FeatureFlagService.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 18 | `php/018_SECOND_ORDER_ProfileAudit.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |

## Failures

### `javascript/006_SAFE_express_orders_repository.js`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Explanation: High risk score (90%) from ML model.

### `javascript/010_SAFE_reports_query_builder.js`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / BLIND`
- Risk score: `0.8759`
- Explanation: High risk score (88%) from ML model.

### `java/011_SAFE_SpringOrderRepository.java`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9295`
- Explanation: High risk score (93%) from ML model.

### `php/015_SAFE_PdoInventoryRepository.php`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Patterns: `SQL_CONCAT | UNSAFE_EXEC`
- Explanation: SQL injection pattern detected: SQL_CONCAT + UNSAFE_EXEC. Risk score: 90%. File analysed in 4 chunk(s) — worst chunk scored 90%.
