# SQLi Test Suite Results

- Total: **32**
- Passed: **32**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_nested_allowlist_decoys.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `python/002_IN_BAND_helper_returns_raw_order.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 3 | `python/003_BLIND_nested_exists_helper.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 4 | `python/004_SECOND_ORDER_stored_filter_chain.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 5 | `python/005_SAFE_db_value_as_param_long_gap.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 6 | `python/006_IN_BAND_execute_alias.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9983 | ✅ |
| 7 | `python/007_SAFE_sql_strings_comments_only.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 8 | `python/008_BLIND_time_based.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 9 | `javascript/009_SAFE_sequelize_replacements_decoy.js` | SAFE / NONE | SAFE / NONE | 0.0009 | ✅ |
| 10 | `javascript/010_IN_BAND_replacements_exist_template_used.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 11 | `javascript/011_BLIND_rows_length_permission.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 12 | `javascript/012_SECOND_ORDER_cache_order_clause.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 13 | `javascript/013_SAFE_sqlite_params_spread_decoy.js` | SAFE / NONE | SAFE / NONE | 0.0168 | ✅ |
| 14 | `javascript/014_IN_BAND_alias_bind_raw_table.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 15 | `javascript/015_SAFE_comments_only.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 16 | `javascript/016_BLIND_time_based_template.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 17 | `java/017_SAFE_named_jdbc_params_decoy.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 18 | `java/018_IN_BAND_jdbc_concat_with_param_decoy.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9943 | ✅ |
| 19 | `java/019_BLIND_exists_helper.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 20 | `java/020_SECOND_ORDER_stored_sql_helper.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9994 | ✅ |
| 21 | `java/021_SAFE_rs_value_bound_param.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 22 | `java/022_IN_BAND_stream_joined_ids.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 23 | `java/023_SAFE_comments_only.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 24 | `java/024_BLIND_time_based_statement.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 25 | `php/025_SAFE_pdo_allowlist_clamp_decoys.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 26 | `php/026_IN_BAND_allowlist_exists_raw_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 27 | `php/027_BLIND_fetch_assoc_helper.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 28 | `php/028_SECOND_ORDER_config_order_helper.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9998 | ✅ |
| 29 | `php/029_SAFE_db_value_bound_param.php` | SAFE / NONE | SAFE / NONE | 0.0054 | ✅ |
| 30 | `php/030_IN_BAND_query_alias_raw.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9967 | ✅ |
| 31 | `php/031_SAFE_comments_only.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 32 | `php/032_BLIND_time_based_raw.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |