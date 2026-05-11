# SQLi Test Suite Results

- Total: **96**
- Passed: **76**
- Failed: **20**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_safe_orm_bind_params.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 2 | `python/002_SAFE_safe_query_builder_chain.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 3 | `python/003_SAFE_safe_enum_order_direction.py` | SAFE / NONE | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 4 | `python/004_SAFE_safe_group_by_allowlist.py` | SAFE / NONE | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 5 | `python/005_SAFE_safe_int_cast_identifier.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 6 | `python/006_SAFE_safe_constant_concat.py` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 7 | `python/007_IN_BAND_unsafe_raw_orm_template.py` | VULNERABLE / IN_BAND | SAFE / NONE | 0.25 | ❌ |
| 8 | `python/008_IN_BAND_unsafe_fake_escape_replace.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 9 | `python/009_IN_BAND_unsafe_blacklist_sanitizer.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 10 | `python/010_IN_BAND_unsafe_raw_order_direction.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 11 | `python/011_IN_BAND_unsafe_raw_group_having.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 12 | `python/012_IN_BAND_unsafe_error_based_cast.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 13 | `python/013_IN_BAND_unsafe_raw_collate.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 14 | `python/014_IN_BAND_unsafe_raw_join_target.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 15 | `python/015_BLIND_blind_waitfor_delay.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 16 | `python/016_BLIND_blind_benchmark_sleep.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 17 | `python/017_BLIND_blind_case_when_exists.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 18 | `python/018_BLIND_blind_oob_like_dns_unc.py` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 19 | `python/019_SECOND_ORDER_second_admin_saved_search.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 20 | `python/020_SECOND_ORDER_second_dashboard_widget_config.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 21 | `python/021_SECOND_ORDER_second_tenant_policy_cache.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 22 | `python/022_SECOND_ORDER_second_stored_sort_direction.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 23 | `python/023_SECOND_ORDER_second_stored_procedure_body.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 24 | `python/024_SECOND_ORDER_second_serialized_report_filter.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 25 | `javascript/025_SAFE_safe_orm_bind_params.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 26 | `javascript/026_SAFE_safe_query_builder_chain.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 27 | `javascript/027_SAFE_safe_enum_order_direction.js` | SAFE / NONE | SUSPICIOUS / IN_BAND | 0.6319 | ❌ |
| 28 | `javascript/028_SAFE_safe_group_by_allowlist.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 29 | `javascript/029_SAFE_safe_int_cast_identifier.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 30 | `javascript/030_SAFE_safe_constant_concat.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 31 | `javascript/031_IN_BAND_unsafe_raw_orm_template.js` | VULNERABLE / IN_BAND | SAFE / NONE | 0.25 | ❌ |
| 32 | `javascript/032_IN_BAND_unsafe_fake_escape_replace.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 33 | `javascript/033_IN_BAND_unsafe_blacklist_sanitizer.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 34 | `javascript/034_IN_BAND_unsafe_raw_order_direction.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 35 | `javascript/035_IN_BAND_unsafe_raw_group_having.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 36 | `javascript/036_IN_BAND_unsafe_error_based_cast.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 37 | `javascript/037_IN_BAND_unsafe_raw_collate.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 38 | `javascript/038_IN_BAND_unsafe_raw_join_target.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 39 | `javascript/039_BLIND_blind_waitfor_delay.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9937 | ✅ |
| 40 | `javascript/040_BLIND_blind_benchmark_sleep.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 41 | `javascript/041_BLIND_blind_case_when_exists.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 42 | `javascript/042_BLIND_blind_oob_like_dns_unc.js` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 43 | `javascript/043_SECOND_ORDER_second_admin_saved_search.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 44 | `javascript/044_SECOND_ORDER_second_dashboard_widget_config.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 45 | `javascript/045_SECOND_ORDER_second_tenant_policy_cache.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 46 | `javascript/046_SECOND_ORDER_second_stored_sort_direction.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 47 | `javascript/047_SECOND_ORDER_second_stored_procedure_body.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 48 | `javascript/048_SECOND_ORDER_second_serialized_report_filter.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 49 | `java/049_SAFE_safe_orm_bind_params.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 50 | `java/050_SAFE_safe_query_builder_chain.java` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 51 | `java/051_SAFE_safe_enum_order_direction.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 52 | `java/052_SAFE_safe_group_by_allowlist.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 53 | `java/053_SAFE_safe_int_cast_identifier.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 54 | `java/054_SAFE_safe_constant_concat.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 55 | `java/055_IN_BAND_unsafe_raw_orm_template.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 56 | `java/056_IN_BAND_unsafe_fake_escape_replace.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 57 | `java/057_IN_BAND_unsafe_blacklist_sanitizer.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 58 | `java/058_IN_BAND_unsafe_raw_order_direction.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 59 | `java/059_IN_BAND_unsafe_raw_group_having.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 60 | `java/060_IN_BAND_unsafe_error_based_cast.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 61 | `java/061_IN_BAND_unsafe_raw_collate.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 62 | `java/062_IN_BAND_unsafe_raw_join_target.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 63 | `java/063_BLIND_blind_waitfor_delay.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 64 | `java/064_BLIND_blind_benchmark_sleep.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 65 | `java/065_BLIND_blind_case_when_exists.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 66 | `java/066_BLIND_blind_oob_like_dns_unc.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 67 | `java/067_SECOND_ORDER_second_admin_saved_search.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 68 | `java/068_SECOND_ORDER_second_dashboard_widget_config.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 69 | `java/069_SECOND_ORDER_second_tenant_policy_cache.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 70 | `java/070_SECOND_ORDER_second_stored_sort_direction.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 71 | `java/071_SECOND_ORDER_second_stored_procedure_body.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 72 | `java/072_SECOND_ORDER_second_serialized_report_filter.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 73 | `php/073_SAFE_safe_orm_bind_params.php` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 74 | `php/074_SAFE_safe_query_builder_chain.php` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 75 | `php/075_SAFE_safe_enum_order_direction.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 76 | `php/076_SAFE_safe_group_by_allowlist.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 77 | `php/077_SAFE_safe_int_cast_identifier.php` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 78 | `php/078_SAFE_safe_constant_concat.php` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 79 | `php/079_IN_BAND_unsafe_raw_orm_template.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 80 | `php/080_IN_BAND_unsafe_fake_escape_replace.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 81 | `php/081_IN_BAND_unsafe_blacklist_sanitizer.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 82 | `php/082_IN_BAND_unsafe_raw_order_direction.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 83 | `php/083_IN_BAND_unsafe_raw_group_having.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 84 | `php/084_IN_BAND_unsafe_error_based_cast.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 85 | `php/085_IN_BAND_unsafe_raw_collate.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 86 | `php/086_IN_BAND_unsafe_raw_join_target.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 87 | `php/087_BLIND_blind_waitfor_delay.php` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 88 | `php/088_BLIND_blind_benchmark_sleep.php` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 89 | `php/089_BLIND_blind_case_when_exists.php` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 90 | `php/090_BLIND_blind_oob_like_dns_unc.php` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 91 | `php/091_SECOND_ORDER_second_admin_saved_search.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 92 | `php/092_SECOND_ORDER_second_dashboard_widget_config.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 93 | `php/093_SECOND_ORDER_second_tenant_policy_cache.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 94 | `php/094_SECOND_ORDER_second_stored_sort_direction.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 95 | `php/095_SECOND_ORDER_second_stored_procedure_body.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |
| 96 | `php/096_SECOND_ORDER_second_serialized_report_filter.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / IN_BAND | 1.0 | ❌ |

## Failures

### `python/003_SAFE_safe_enum_order_direction.py`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `UNSAFE_EXEC`
- Explanation: SQL injection pattern detected: UNSAFE_EXEC. Risk score: 100%. File analysed in 4 chunk(s) — worst chunk scored 100%.

### `python/004_SAFE_safe_group_by_allowlist.py`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `UNSAFE_EXEC`
- Explanation: SQL injection pattern detected: UNSAFE_EXEC. Risk score: 100%. File analysed in 4 chunk(s) — worst chunk scored 100%.

### `python/006_SAFE_safe_constant_concat.py`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Explanation: SQL injection evidence detected by source/sink analysis. Risk score: 90%.

### `python/007_IN_BAND_unsafe_raw_orm_template.py`

- Expected: `VULNERABLE / IN_BAND`
- Actual: `SAFE / NONE`
- Risk score: `0.25`
- Explanation: No SQL injection patterns detected. Risk score: 25%.

### `python/018_BLIND_blind_oob_like_dns_unc.py`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `UNSAFE_EXEC`
- Explanation: SQL injection pattern detected: UNSAFE_EXEC. Risk score: 100%. File analysed in 4 chunk(s) — worst chunk scored 100%.

### `python/021_SECOND_ORDER_second_tenant_policy_cache.py`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 90%. File analysed in 4 chunk(s) — worst chunk scored 90%.

### `javascript/027_SAFE_safe_enum_order_direction.js`

- Expected: `SAFE / NONE`
- Actual: `SUSPICIOUS / IN_BAND`
- Risk score: `0.6319`
- Patterns: `UNSAFE_EXEC`
- Explanation: Suspicious patterns detected (score 63%). Manual review recommended.

### `javascript/031_IN_BAND_unsafe_raw_orm_template.js`

- Expected: `VULNERABLE / IN_BAND`
- Actual: `SAFE / NONE`
- Risk score: `0.25`
- Explanation: No SQL injection patterns detected. Risk score: 25%.

### `javascript/042_BLIND_blind_oob_like_dns_unc.js`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `UNSAFE_EXEC`
- Explanation: SQL injection pattern detected: UNSAFE_EXEC. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/078_SAFE_safe_constant_concat.php`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Explanation: SQL injection evidence detected by source/sink analysis. Risk score: 90%.

### `php/087_BLIND_blind_waitfor_delay.php`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/088_BLIND_blind_benchmark_sleep.php`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/089_BLIND_blind_case_when_exists.php`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/090_BLIND_blind_oob_like_dns_unc.php`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/091_SECOND_ORDER_second_admin_saved_search.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/092_SECOND_ORDER_second_dashboard_widget_config.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/093_SECOND_ORDER_second_tenant_policy_cache.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/094_SECOND_ORDER_second_stored_sort_direction.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/095_SECOND_ORDER_second_stored_procedure_body.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.

### `php/096_SECOND_ORDER_second_serialized_report_filter.php`

- Expected: `VULNERABLE / SECOND_ORDER`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `1.0`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 1 chunk(s) — worst chunk scored 100%.
