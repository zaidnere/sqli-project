# SQLi Test Suite Results

- Total: **32**
- Passed: **32**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_sql_like_string_no_sink.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 2 | `python/002_IN_BAND_direct_raw_named_cached.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 3 | `python/003_SECOND_ORDER_real_saved_filter.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 4 | `python/004_BLIND_time_based_pg_sleep.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 5 | `python/005_BLIND_count_helper.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 6 | `python/006_SAFE_db_loaded_value_param.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 7 | `python/007_IN_BAND_direct_raw_ids_join.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 8 | `python/008_SAFE_allowlist_decoy_stored_word.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 9 | `javascript/009_SAFE_sql_like_string_no_sink.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 10 | `javascript/010_IN_BAND_direct_template_named_storedSegment.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 11 | `javascript/011_SECOND_ORDER_real_saved_segment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 12 | `javascript/012_BLIND_feature_count_helper.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 13 | `javascript/013_BLIND_time_based_sleep_template.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 14 | `javascript/014_IN_BAND_direct_raw_ids_cached_name.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 15 | `javascript/015_SAFE_db_loaded_value_param.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 16 | `javascript/016_SAFE_sequelize_replacements_decoy.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 17 | `java/017_SAFE_named_parameter_jdbc_template.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 18 | `java/018_IN_BAND_named_parameter_concat_email.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9973 | ✅ |
| 19 | `java/019_SECOND_ORDER_real_config_condition.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 20 | `java/020_BLIND_time_based_sleep.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9999 | ✅ |
| 21 | `java/021_BLIND_count_helper.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 22 | `java/022_SAFE_comments_string_no_sink.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 23 | `java/023_SAFE_db_loaded_value_param.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 24 | `java/024_IN_BAND_raw_ids_joining.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 25 | `php/025_SAFE_comment_string_no_sink.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 26 | `php/026_IN_BAND_direct_mysqli_customer_search.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 27 | `php/027_IN_BAND_laravel_raw_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 28 | `php/028_IN_BAND_raw_ids_implode.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 29 | `php/029_SECOND_ORDER_real_saved_filter.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 30 | `php/030_SAFE_db_value_as_param.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 31 | `php/031_BLIND_time_based_sleep.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 32 | `php/032_IN_BAND_callable_query_alias_raw.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9996 | ✅ |