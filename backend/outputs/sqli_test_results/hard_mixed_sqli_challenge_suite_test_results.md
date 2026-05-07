# SQLi Test Suite Results

- Total: **80**
- Passed: **80**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_exact_helper_whitelist_order_by.py` | SAFE / NONE | SAFE / NONE | 0.0006 | ✅ |
| 2 | `python/002_SAFE_placeholder_list_builder.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 3 | `python/003_SAFE_numeric_limit_offset_bounds.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 4 | `python/004_SAFE_db_loaded_value_reused_as_param.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 5 | `python/005_SAFE_static_migration_executescript.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 6 | `python/006_IN_BAND_fstring_where_direct.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 7 | `python/007_IN_BAND_whitelist_computed_but_raw_order_used.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 8 | `python/008_IN_BAND_joined_ids_raw_in.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 9 | `python/009_IN_BAND_executescript_dynamic.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9995 | ✅ |
| 10 | `python/010_IN_BAND_raw_table_name.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 11 | `python/011_BLIND_count_gt_zero_raw.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 12 | `python/012_BLIND_helper_bool_raw_fetchone.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 13 | `python/013_BLIND_role_check_raw.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 14 | `python/014_BLIND_token_raw.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 15 | `python/015_BLIND_active_session_raw.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 16 | `python/016_SECOND_ORDER_saved_filter_reused.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 17 | `python/017_SECOND_ORDER_cached_row_fragment.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 18 | `python/018_SECOND_ORDER_config_fragment.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 19 | `python/019_SECOND_ORDER_stored_script_executescript.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 20 | `python/020_SECOND_ORDER_stored_order_expression.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 21 | `javascript/021_SAFE_sqlite_param_array.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 22 | `javascript/022_SAFE_set_whitelist_order.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 23 | `javascript/023_SAFE_placeholder_in_list.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 24 | `javascript/024_SAFE_number_limit_offset.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 25 | `javascript/025_SAFE_db_loaded_value_as_param.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 26 | `javascript/026_IN_BAND_template_where.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 27 | `javascript/027_IN_BAND_whitelist_unused_raw_order.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 28 | `javascript/028_IN_BAND_joined_ids.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 29 | `javascript/029_IN_BAND_raw_limit_offset.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 30 | `javascript/030_IN_BAND_db_exec_template.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 31 | `javascript/031_BLIND_count_bool.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9886 | ✅ |
| 32 | `javascript/032_BLIND_feature_flag.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 33 | `javascript/033_BLIND_permission_check.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 34 | `javascript/034_BLIND_login_bool.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 35 | `javascript/035_BLIND_token_exists.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 36 | `javascript/036_SECOND_ORDER_saved_segment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 37 | `javascript/037_SECOND_ORDER_cached_fragment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 38 | `javascript/038_SECOND_ORDER_db_loaded_order.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9992 | ✅ |
| 39 | `javascript/039_SECOND_ORDER_stored_query.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 40 | `javascript/040_SECOND_ORDER_saved_filter_builder.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 41 | `java/041_SAFE_prepared_statement_basic.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 42 | `java/042_SAFE_resultset_next_prepared_bool.java` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 43 | `java/043_SAFE_set_contains_order_by.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 44 | `java/044_SAFE_db_value_reused_as_param.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 45 | `java/045_SAFE_numeric_bounds_limit.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 46 | `java/046_IN_BAND_statement_concat_where.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 47 | `java/047_IN_BAND_whitelist_unused_raw_order.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 48 | `java/048_IN_BAND_raw_order.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 49 | `java/049_IN_BAND_joined_ids.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 50 | `java/050_IN_BAND_raw_limit_offset.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 51 | `java/051_BLIND_count_next_statement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 52 | `java/052_BLIND_login_statement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9998 | ✅ |
| 53 | `java/053_BLIND_permission_raw.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9998 | ✅ |
| 54 | `java/054_BLIND_is_admin_raw.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 55 | `java/055_BLIND_token_raw.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9993 | ✅ |
| 56 | `java/056_SECOND_ORDER_getstring_fragment.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9983 | ✅ |
| 57 | `java/057_SECOND_ORDER_saved_note_condition.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 58 | `java/058_SECOND_ORDER_db_loaded_order.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 59 | `java/059_SECOND_ORDER_stored_query_run.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 60 | `java/060_SECOND_ORDER_cached_config_where.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 61 | `php/061_SAFE_pdo_prepare_execute.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 62 | `php/062_SAFE_array_whitelist_order.php` | SAFE / NONE | SAFE / NONE | 0.0106 | ✅ |
| 63 | `php/063_SAFE_placeholder_in_list.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 64 | `php/064_SAFE_numeric_bounds.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 65 | `php/065_SAFE_db_value_as_param.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 66 | `php/066_IN_BAND_mysqli_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 67 | `php/067_IN_BAND_whitelist_unused_raw.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 68 | `php/068_IN_BAND_raw_ids_implode.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 69 | `php/069_IN_BAND_raw_order.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 70 | `php/070_IN_BAND_pdo_query_raw.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 71 | `php/071_BLIND_count_bool.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 72 | `php/072_BLIND_login_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 73 | `php/073_BLIND_feature_flag_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 74 | `php/074_BLIND_permission_exists.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 75 | `php/075_BLIND_token_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 76 | `php/076_SECOND_ORDER_fetch_assoc_reuse.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 77 | `php/077_SECOND_ORDER_saved_filter.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 78 | `php/078_SECOND_ORDER_profile_audit_where.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 79 | `php/079_SECOND_ORDER_stored_sql_run.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 80 | `php/080_SECOND_ORDER_config_fragment.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |