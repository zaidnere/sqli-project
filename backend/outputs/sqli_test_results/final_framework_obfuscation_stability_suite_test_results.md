# SQLi Test Suite Results

- Total: **64**
- Passed: **64**
- Failed: **0**

| # | File | Expected | Actual | Risk | Pass |
|---:|---|---|---|---:|---|
| 1 | `python/001_SAFE_django_raw_params_order_allowlist.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 2 | `python/002_IN_BAND_django_raw_email_concat.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 3 | `python/003_BLIND_django_permission_exists.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 4 | `python/004_SECOND_ORDER_django_saved_filter_helper.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 5 | `python/005_SAFE_sqlalchemy_text_params.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 6 | `python/006_IN_BAND_sqlalchemy_text_fstring.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 7 | `python/007_SAFE_obfuscated_params_builder.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 8 | `python/008_IN_BAND_obfuscated_alias_execute.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 9 | `python/009_SAFE_huge_repository_one_thousand_lines.py` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 10 | `python/010_SECOND_ORDER_huge_stored_sql_late_sink.py` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 11 | `python/011_SAFE_broken_looking_comments_hebrew.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 12 | `python/012_BLIND_helper_returns_bool.py` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 13 | `python/013_SAFE_multi_query_same_file.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 14 | `python/014_IN_BAND_multi_query_one_unsafe.py` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 15 | `python/015_SAFE_empty_logic_file.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 16 | `python/016_SAFE_broken_syntax_no_crash.py` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 17 | `javascript/017_SAFE_express_sequelize_replacements.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 18 | `javascript/018_IN_BAND_sequelize_template_raw.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 19 | `javascript/019_SAFE_knex_where_params.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 20 | `javascript/020_IN_BAND_knex_raw_order.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 21 | `javascript/021_BLIND_express_session_auth.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9882 | ✅ |
| 22 | `javascript/022_SECOND_ORDER_cache_filter_to_sql.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 23 | `javascript/023_SAFE_params_variable_and_decoys.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 24 | `javascript/024_IN_BAND_exec_template_alias.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 25 | `javascript/025_SAFE_huge_file_allowlist.js` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 26 | `javascript/026_SECOND_ORDER_huge_stored_query.js` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 27 | `javascript/027_SAFE_hebrew_comments.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 28 | `javascript/028_BLIND_feature_count_helper.js` | VULNERABLE / BLIND | VULNERABLE / BLIND | 1.0 | ✅ |
| 29 | `javascript/029_SAFE_multi_query_file.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 30 | `javascript/030_IN_BAND_multi_query_one_unsafe.js` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 31 | `javascript/031_SAFE_only_comments.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 32 | `javascript/032_SAFE_broken_syntax_no_crash.js` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 33 | `java/033_SAFE_spring_jdbctemplate_params.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 34 | `java/034_IN_BAND_spring_jdbctemplate_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 35 | `java/035_SAFE_jpa_native_query_params.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 36 | `java/036_IN_BAND_jpa_native_query_concat.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 37 | `java/037_BLIND_spring_security_check.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 38 | `java/038_SECOND_ORDER_helper_return_fragment.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 39 | `java/039_SAFE_set_contains_decoys.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 40 | `java/040_IN_BAND_raw_order_despite_decoy.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 1.0 | ✅ |
| 41 | `java/041_SAFE_huge_prepared.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 42 | `java/042_SECOND_ORDER_huge_stored_query.java` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 43 | `java/043_SAFE_hebrew_comments.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 44 | `java/044_BLIND_token_helper.java` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9932 | ✅ |
| 45 | `java/045_SAFE_multi_query_file.java` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 46 | `java/046_IN_BAND_multi_query_one_unsafe.java` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9997 | ✅ |
| 47 | `java/047_SAFE_only_comments.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 48 | `java/048_SAFE_broken_syntax_no_crash.java` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 49 | `php/049_SAFE_laravel_db_select_bindings.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 50 | `php/050_IN_BAND_laravel_db_raw_concat.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 51 | `php/051_SAFE_pdo_querybuilder_decoys.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 52 | `php/052_IN_BAND_pdo_raw_order_decoy.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 53 | `php/053_BLIND_mysqli_login.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 54 | `php/054_SECOND_ORDER_pdo_saved_filter_helper.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 55 | `php/055_SAFE_placeholder_list.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 56 | `php/056_IN_BAND_implode_raw_ids.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 57 | `php/057_SAFE_huge_pdo_repo.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 58 | `php/058_SECOND_ORDER_huge_stored_sql.php` | VULNERABLE / SECOND_ORDER | VULNERABLE / SECOND_ORDER | 0.9 | ✅ |
| 59 | `php/059_SAFE_hebrew_comments.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 60 | `php/060_BLIND_permission_fetch_assoc.php` | VULNERABLE / BLIND | VULNERABLE / BLIND | 0.9 | ✅ |
| 61 | `php/061_SAFE_multi_query_file.php` | SAFE / NONE | SAFE / NONE | 0.08 | ✅ |
| 62 | `php/062_IN_BAND_multi_query_one_unsafe.php` | VULNERABLE / IN_BAND | VULNERABLE / IN_BAND | 0.9 | ✅ |
| 63 | `php/063_SAFE_only_comments.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |
| 64 | `php/064_SAFE_broken_syntax_no_crash.php` | SAFE / NONE | SAFE / NONE | 0.25 | ✅ |