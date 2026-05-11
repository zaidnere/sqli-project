# SQLi Test Suite Results

- Total: **20**
- Passed: **18**
- Failed: **2**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `javascript/001_SAFE_object_map_alias_chain_order.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `javascript/002_IN_BAND_object_map_safe_then_raw_alias_used.js` | VULNERABLE / IN_BAND | SAFE / NONE | 0.08 | ❌ |
| 3 | `javascript/003_SAFE_helper_allowlist_return_alias.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 4 | `javascript/004_IN_BAND_helper_called_but_request_used.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 5 | `javascript/005_SECOND_ORDER_db_loaded_sql_fragment_property_chain.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 1.0 | ✅ |
| 6 | `javascript/006_IN_BAND_request_config_where_clause_raw.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 7 | `javascript/007_SECOND_ORDER_cache_config_order_clause.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9999 | ✅ |
| 8 | `javascript/008_SAFE_config_value_as_bound_parameter.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 9 | `javascript/009_BLIND_count_bool_return.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 10 | `javascript/010_IN_BAND_count_returned_as_data.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 11 | `php/011_SAFE_property_array_alias_chain_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 12 | `php/012_IN_BAND_property_array_safe_then_raw_alias_used.php` | VULNERABLE / IN_BAND | SAFE / NONE | 0.08 | ❌ |
| 13 | `php/013_SAFE_match_alias_chain_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 14 | `php/014_IN_BAND_match_exists_but_raw_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 15 | `php/015_SAFE_helper_return_alias_chain_order.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 16 | `php/016_IN_BAND_helper_called_but_request_used.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 17 | `php/017_BLIND_count_alias_boolean_return_with_and.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 18 | `php/018_BLIND_count_alias_boolean_return_with_if.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9997 | ✅ |
| 19 | `php/019_IN_BAND_count_alias_json_response.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9998 | ✅ |
| 20 | `php/020_SAFE_pdo_parameterized_count_bool_guard.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |

## Failures

### `javascript/002_IN_BAND_object_map_safe_then_raw_alias_used.js`

- Expected: `VULNERABLE / IN_BAND`
- Actual: `SAFE / NONE`
- Risk score: `0.08`
- Explanation: No SQL injection patterns detected. Risk score: 8%.

### `php/012_IN_BAND_property_array_safe_then_raw_alias_used.php`

- Expected: `VULNERABLE / IN_BAND`
- Actual: `SAFE / NONE`
- Risk score: `0.08`
- Explanation: No SQL injection patterns detected. Risk score: 8%.
