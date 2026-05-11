# SQLi Test Suite Results

- Total: **28**
- Passed: **28**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `javascript/001_SAFE_object_map_order_exact_var.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `javascript/002_SAFE_map_get_order_exact_var.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 3 | `javascript/003_SAFE_helper_pick_sort_order.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 4 | `javascript/004_SAFE_set_has_order_exact_var.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 5 | `javascript/005_IN_BAND_object_map_computed_but_raw_used.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 6 | `javascript/006_IN_BAND_set_has_but_raw_used.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 7 | `javascript/007_SECOND_ORDER_saved_segment_where_clause.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 8 | `javascript/008_SECOND_ORDER_cached_filter_sql.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 9 | `javascript/009_IN_BAND_direct_saved_segment_name_raw.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 10 | `javascript/010_SAFE_db_loaded_value_as_param_not_fragment.js` | SAFE / NONE | SAFE / NONE | 0.0209 | ✅ |
| 11 | `javascript/011_SAFE_sequelize_replacements_named.js` | SAFE / NONE | SAFE / NONE | 0.0001 | ✅ |
| 12 | `javascript/012_IN_BAND_sequelize_template_raw.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 13 | `php/013_SAFE_array_whitelist_order_exact_var.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 14 | `php/014_SAFE_local_array_whitelist_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 15 | `php/015_SAFE_match_expression_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 16 | `php/016_SAFE_helper_pick_sort_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 17 | `php/017_IN_BAND_array_whitelist_computed_but_raw_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9991 | ✅ |
| 18 | `php/018_IN_BAND_helper_safe_but_raw_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 19 | `php/019_BLIND_count_alias_c_gt_zero.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 20 | `php/020_BLIND_fetch_assoc_row_exists.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 21 | `php/021_BLIND_num_rows_gt_zero.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 22 | `php/022_BLIND_helper_returns_bool.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 23 | `php/023_BLIND_feature_flag_enabled.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 24 | `php/024_IN_BAND_raw_search_fetch_all.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 25 | `php/025_IN_BAND_raw_count_displayed_as_data.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9999 | ✅ |
| 26 | `php/026_SAFE_parameterized_count_bool.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 27 | `php/027_SAFE_static_pdo_query_no_input.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 28 | `php/028_SECOND_ORDER_saved_filter_where_clause.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |