# SQLi Test Suite Results

- Total: **40**
- Passed: **40**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_basic_parameterized_lookup.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 2 | `python/002_SAFE_insert_parameterized.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 3 | `python/003_SAFE_update_parameterized.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 4 | `python/004_IN_BAND_select_raw_email.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 5 | `python/005_IN_BAND_update_raw_status.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 6 | `python/006_BLIND_login_boolean.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 7 | `python/007_BLIND_permission_row_exists.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 8 | `python/008_SECOND_ORDER_saved_where_clause.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 9 | `python/009_SECOND_ORDER_stored_full_query.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 10 | `python/010_SAFE_db_loaded_value_as_param.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 11 | `javascript/011_SAFE_parameterized_get.js` | SAFE / NONE | SAFE / NONE | 0.0003 | ✅ |
| 12 | `javascript/012_SAFE_parameterized_insert.js` | SAFE / NONE | SAFE / NONE | 0.0002 | ✅ |
| 13 | `javascript/013_IN_BAND_template_email_search.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 14 | `javascript/014_IN_BAND_concat_update_status.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 15 | `javascript/015_BLIND_login_row_exists.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 16 | `javascript/016_BLIND_count_gt_zero.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 17 | `javascript/017_SECOND_ORDER_saved_segment.py.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 18 | `javascript/018_SECOND_ORDER_stored_query_runner.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9999 | ✅ |
| 19 | `javascript/019_SAFE_db_loaded_value_as_param.js` | SAFE / NONE | SAFE / NONE | 0.0209 | ✅ |
| 20 | `javascript/020_SAFE_plain_service_no_sql.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 21 | `java/021_SAFE_prepared_select.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 22 | `java/022_SAFE_prepared_update.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 23 | `java/023_IN_BAND_statement_where_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 24 | `java/024_IN_BAND_statement_update_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 25 | `java/025_BLIND_login_rs_next.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 26 | `java/026_BLIND_count_gt_zero.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 27 | `java/027_SECOND_ORDER_saved_where_clause.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 28 | `java/028_SECOND_ORDER_stored_query.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9999 | ✅ |
| 29 | `java/029_SAFE_db_loaded_value_as_param.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 30 | `java/030_SAFE_plain_no_sql.java` | SAFE / NONE | SAFE / NONE | 0.0765 | ✅ |
| 31 | `php/031_SAFE_pdo_select_parameterized.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 32 | `php/032_SAFE_pdo_update_parameterized.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 33 | `php/033_SAFE_placeholder_in_list.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 34 | `php/034_BLIND_login_num_rows.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 35 | `php/035_BLIND_count_bool.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 36 | `php/036_SECOND_ORDER_saved_where_clause.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 37 | `php/037_SECOND_ORDER_stored_query.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 38 | `php/038_SAFE_db_loaded_value_as_param.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 39 | `php/039_SAFE_plain_service_no_sql.php` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 40 | `php/040_SAFE_pdo_static_query_no_input.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |