# SQLi Test Suite Results

- Total: **40**
- Passed: **40**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_NONE_safe_direct_whitelist_order_by.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 2 | `python/002_IN_BAND_vuln_raw_order_by.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 3 | `python/003_IN_BAND_vuln_whitelist_computed_but_unused.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 4 | `python/004_NONE_safe_placeholder_list_in.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 5 | `python/005_IN_BAND_vuln_joined_in_list.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 6 | `python/006_NONE_safe_limit_offset_int_bounds.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 7 | `python/007_IN_BAND_vuln_raw_limit_offset.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 8 | `python/008_BLIND_vuln_count_gt_zero.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 9 | `python/009_BLIND_vuln_fetchone_helper_bool.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 10 | `python/010_NONE_safe_parameterized_boolean.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 11 | `python/011_SECOND_ORDER_vuln_db_value_reuse.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 12 | `python/012_SECOND_ORDER_vuln_cached_fragment.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 13 | `python/013_NONE_safe_db_value_parameterized.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 14 | `python/014_NONE_safe_static_executescript.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 15 | `python/015_IN_BAND_vuln_executescript_fstring.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 16 | `python/016_IN_BAND_vuln_replace_sanitized_like.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 17 | `python/017_NONE_safe_enum_parameterized.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 18 | `python/018_IN_BAND_vuln_alias_to_execute.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 19 | `python/019_NONE_safe_dict_map_table.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 20 | `python/020_IN_BAND_vuln_dynamic_table_raw.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9277 | ✅ |
| 21 | `javascript/021_IN_BAND_vuln_template_where.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9991 | ✅ |
| 22 | `javascript/022_NONE_safe_parameterized_query.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 23 | `javascript/023_BLIND_vuln_boolean_count.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 24 | `javascript/024_SECOND_ORDER_vuln_cached_fragment.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 25 | `javascript/025_NONE_safe_whitelist_order_by.js` | SAFE / NONE | SAFE / NONE | 0.0411 | ✅ |
| 26 | `javascript/026_IN_BAND_vuln_raw_order_by.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9414 | ✅ |
| 27 | `javascript/027_NONE_safe_placeholder_in_list.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 28 | `javascript/028_IN_BAND_vuln_joined_ids.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 29 | `java/029_IN_BAND_vuln_statement_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9971 | ✅ |
| 30 | `java/030_NONE_safe_prepared_statement.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 31 | `java/031_BLIND_vuln_boolean_login.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 32 | `java/032_SECOND_ORDER_vuln_stored_note.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 33 | `java/033_NONE_safe_whitelist_order_by.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 34 | `java/034_IN_BAND_vuln_raw_order_by.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9969 | ✅ |
| 35 | `php/035_IN_BAND_vuln_mysqli_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 36 | `php/036_NONE_safe_prepared_stmt.php` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 37 | `php/037_BLIND_vuln_count_bool.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 38 | `php/038_SECOND_ORDER_vuln_db_reuse.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 39 | `php/039_NONE_safe_whitelist_order_by.php` | SAFE / NONE | SAFE / NONE | 0.1 | ✅ |
| 40 | `php/040_IN_BAND_vuln_raw_order_by.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |