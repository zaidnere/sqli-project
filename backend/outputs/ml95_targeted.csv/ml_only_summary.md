# ML-only Suite Evaluation
- Total: **32**
- Threshold: **0.50**
- Binary ML accuracy: **20/32** (62.50%)
- Full ML label+type accuracy: **18/32** (56.25%)
- Expected attack distribution: `{'BLIND': 3, 'NONE': 16, 'SECOND_ORDER': 3, 'IN_BAND': 10}`
- ML attack distribution: `{'IN_BAND': 17, 'BLIND': 2, 'SECOND_ORDER': 7, 'NONE': 6}`

## Failures

- `targeted_next_debug_suite/java/017_BLIND_vuln_resultset_next.java` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/java/018_NONE_safe_resultset_next_prepared.java` expected `SAFE / NONE` got `VULNERABLE / BLIND` risk `0.9741`
- `targeted_next_debug_suite/java/024_NONE_safe_resultset_param_reuse.java` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `targeted_next_debug_suite/java/029_NONE_safe_set_contains_order_by.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/javascript/013_NONE_safe_limit_offset_number_js.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `targeted_next_debug_suite/javascript/014_IN_BAND_vuln_raw_limit_offset_js.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `targeted_next_debug_suite/javascript/027_NONE_safe_set_has_order_by_js.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/php/019_BLIND_vuln_count_bool_php.php` expected `VULNERABLE / BLIND` got `SAFE / NONE` risk `0.001`
- `targeted_next_debug_suite/php/026_NONE_safe_fetch_assoc_param_reuse.php` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9916`
- `targeted_next_debug_suite/php/031_NONE_safe_array_map_order_by.php` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/python/001_NONE_safe_direct_whitelist_order_by.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/python/003_NONE_safe_helper_pick_allowed_order_by.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/python/005_NONE_safe_dict_map_table.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `targeted_next_debug_suite/python/011_NONE_safe_limit_offset_int_minmax.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
