# SQLi Test Suite Results

- Total: **32**
- Passed: **32**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_NONE_safe_direct_whitelist_order_by.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 2 | `python/002_IN_BAND_vuln_whitelist_computed_but_raw_used.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9976 | ✅ |
| 3 | `python/003_NONE_safe_helper_pick_allowed_order_by.py` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 4 | `python/004_IN_BAND_vuln_helper_whitelist_but_raw_used.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 5 | `python/005_NONE_safe_dict_map_table.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 6 | `python/006_IN_BAND_vuln_dict_map_computed_but_raw_used.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 7 | `python/007_NONE_safe_placeholder_list_execute_params.py` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 8 | `python/008_IN_BAND_vuln_joined_raw_ids.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 9 | `javascript/009_NONE_safe_placeholder_list_js.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 10 | `javascript/010_IN_BAND_vuln_joined_ids_js.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 11 | `python/011_NONE_safe_limit_offset_int_minmax.py` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 12 | `python/012_IN_BAND_vuln_raw_limit_offset.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 13 | `javascript/013_NONE_safe_limit_offset_number_js.js` | SAFE / NONE | SAFE / NONE | 0.0015 | ✅ |
| 14 | `javascript/014_IN_BAND_vuln_raw_limit_offset_js.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 15 | `javascript/015_BLIND_vuln_count_bool_js.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 16 | `javascript/016_NONE_safe_count_bool_js.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 17 | `java/017_BLIND_vuln_resultset_next.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 18 | `java/018_NONE_safe_resultset_next_prepared.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 19 | `php/019_BLIND_vuln_count_bool_php.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 20 | `php/020_NONE_safe_count_bool_php.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 21 | `javascript/021_SECOND_ORDER_vuln_cached_fragment_js.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 22 | `javascript/022_NONE_safe_db_value_param_js.js` | SAFE / NONE | SAFE / NONE | 0.0463 | ✅ |
| 23 | `java/023_SECOND_ORDER_vuln_resultset_getstring.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 24 | `java/024_NONE_safe_resultset_param_reuse.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 25 | `php/025_SECOND_ORDER_vuln_fetch_assoc_reuse.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 26 | `php/026_NONE_safe_fetch_assoc_param_reuse.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 27 | `javascript/027_NONE_safe_set_has_order_by_js.js` | SAFE / NONE | SAFE / NONE |  | ✅ |
| 28 | `javascript/028_IN_BAND_vuln_set_has_but_raw_used_js.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 29 | `java/029_NONE_safe_set_contains_order_by.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 30 | `java/030_IN_BAND_vuln_set_contains_but_raw_used.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 31 | `php/031_NONE_safe_array_map_order_by.php` | SAFE / NONE | SAFE / NONE | 0.0101 | ✅ |
| 32 | `php/032_IN_BAND_vuln_array_map_but_raw_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9604 | ✅ |