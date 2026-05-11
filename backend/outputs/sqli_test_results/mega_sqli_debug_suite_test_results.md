# SQLi Test Suite Results

- Total: **40**
- Passed: **40**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_NONE_safe_direct_whitelist_order_by.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 2 | `python/002_IN_BAND_vuln_raw_order_by.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 3 | `python/003_IN_BAND_vuln_whitelist_computed_but_unused.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9976 | ✅ |
| 4 | `python/004_NONE_safe_placeholder_list_in.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 5 | `python/005_IN_BAND_vuln_joined_in_list.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 6 | `python/006_NONE_safe_limit_offset_int_bounds.py` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 7 | `python/007_IN_BAND_vuln_raw_limit_offset.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 8 | `python/008_BLIND_vuln_count_gt_zero.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 9 | `python/009_BLIND_vuln_fetchone_helper_bool.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 10 | `python/010_NONE_safe_parameterized_boolean.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 11 | `python/011_SECOND_ORDER_vuln_db_value_reuse.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 12 | `python/012_SECOND_ORDER_vuln_cached_fragment.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 13 | `python/013_NONE_safe_db_value_parameterized.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 14 | `python/014_NONE_safe_static_executescript.py` | SAFE / NONE | SAFE / NONE | 0.0055 | ✅ |
| 15 | `python/015_IN_BAND_vuln_executescript_fstring.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 16 | `python/016_IN_BAND_vuln_replace_sanitized_like.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 17 | `python/017_NONE_safe_enum_parameterized.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 18 | `python/018_IN_BAND_vuln_alias_to_execute.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 19 | `python/019_NONE_safe_dict_map_table.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 20 | `python/020_IN_BAND_vuln_dynamic_table_raw.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 21 | `javascript/021_IN_BAND_vuln_template_where.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 22 | `javascript/022_NONE_safe_parameterized_query.js` | SAFE / NONE | SAFE / NONE | 0.0452 | ✅ |
| 23 | `javascript/023_BLIND_vuln_boolean_count.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 24 | `javascript/024_SECOND_ORDER_vuln_cached_fragment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 25 | `javascript/025_NONE_safe_whitelist_order_by.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 26 | `javascript/026_IN_BAND_vuln_raw_order_by.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 27 | `javascript/027_NONE_safe_placeholder_in_list.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 28 | `javascript/028_IN_BAND_vuln_joined_ids.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 29 | `java/029_IN_BAND_vuln_statement_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 30 | `java/030_NONE_safe_prepared_statement.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 31 | `java/031_BLIND_vuln_boolean_login.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 32 | `java/032_SECOND_ORDER_vuln_stored_note.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 33 | `java/033_NONE_safe_whitelist_order_by.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 34 | `java/034_IN_BAND_vuln_raw_order_by.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 35 | `php/035_IN_BAND_vuln_mysqli_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 36 | `php/036_NONE_safe_prepared_stmt.php` | SAFE / NONE | SAFE / NONE | 0.001 | ✅ |
| 37 | `php/037_BLIND_vuln_count_bool.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 38 | `php/038_SECOND_ORDER_vuln_db_reuse.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 39 | `php/039_NONE_safe_whitelist_order_by.php` | SAFE / NONE | SAFE / NONE | 0.0101 | ✅ |
| 40 | `php/040_IN_BAND_vuln_raw_order_by.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |