# SQLi Test Suite Results

- Total: **40**
- Passed: **37**
- Failed: **3**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_parameterized_execute.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 2 | `python/002_SAFE_allowlisted_order_by.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 3 | `python/003_IN_BAND_raw_email_concat.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 4 | `python/004_IN_BAND_raw_order_by.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 5 | `python/005_IN_BAND_joined_ids.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 6 | `python/006_BLIND_login_raw.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 7 | `python/007_BLIND_count_gt_zero.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 8 | `python/008_SECOND_ORDER_saved_filter.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 9 | `python/009_SAFE_db_loaded_value_as_param.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 10 | `python/010_SAFE_static_executescript.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 11 | `javascript/011_SAFE_db_all_params.js` | SAFE / NONE | SAFE / NONE | 0.006 | ✅ |
| 12 | `javascript/012_SAFE_allowlisted_order.js` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 13 | `javascript/013_IN_BAND_template_where.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 14 | `javascript/014_IN_BAND_raw_order.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 15 | `javascript/015_IN_BAND_joined_ids.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 16 | `javascript/016_BLIND_session_verifier.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 17 | `javascript/017_BLIND_count_bool.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 18 | `javascript/018_SECOND_ORDER_saved_segment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 19 | `javascript/019_SAFE_db_value_as_param.js` | SAFE / NONE | SAFE / NONE | 0.006 | ✅ |
| 20 | `javascript/020_SAFE_comments_only.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 21 | `java/021_SAFE_prepared_statement.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 22 | `java/022_SAFE_set_contains_order.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 23 | `java/023_IN_BAND_statement_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 24 | `java/024_IN_BAND_raw_order.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 25 | `java/025_IN_BAND_joined_ids.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 26 | `java/026_BLIND_login_statement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 27 | `java/027_BLIND_count_next.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 28 | `java/028_SECOND_ORDER_getstring_fragment.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 29 | `java/029_SAFE_db_value_as_param.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 30 | `java/030_SAFE_comments_only.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 31 | `php/031_SAFE_pdo_prepare_execute.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 32 | `php/032_SAFE_array_whitelist_order.php` | SAFE / NONE | VULNERABLE / IN_BAND | 0.9 | ❌ |
| 33 | `php/033_IN_BAND_mysqli_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9691 | ✅ |
| 34 | `php/034_IN_BAND_raw_order.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 35 | `php/035_IN_BAND_raw_ids_implode.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 36 | `php/036_BLIND_login_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 37 | `php/037_BLIND_count_bool.php` | VULNERABLE / BLIND | VULNERABLE / IN_BAND | 0.9999 | ❌ |
| 38 | `php/038_SECOND_ORDER_saved_filter.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 39 | `php/039_SAFE_db_value_as_param.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 40 | `php/040_SAFE_comments_only.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |

## Failures

### `javascript/012_SAFE_allowlisted_order.js`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Explanation: SQL injection evidence detected by source/sink analysis. Risk score: 90%.

### `php/032_SAFE_array_whitelist_order.php`

- Expected: `SAFE / NONE`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9`
- Explanation: SQL injection evidence detected by source/sink analysis. Risk score: 90%.

### `php/037_BLIND_count_bool.php`

- Expected: `VULNERABLE / BLIND`
- Actual: `VULNERABLE / IN_BAND`
- Risk score: `0.9999`
- Patterns: `SQL_CONCAT`
- Explanation: SQL injection pattern detected: SQL_CONCAT. Risk score: 100%. File analysed in 4 chunk(s) — worst chunk scored 100%.
