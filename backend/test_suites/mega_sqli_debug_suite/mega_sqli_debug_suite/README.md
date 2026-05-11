# Mega SQLi Debug Suite

This suite is designed for large-scale debugging of the SQLi detector.

It includes 40 code files across supported languages:
- Python
- JavaScript
- Java
- PHP

Expected types:
- NONE
- IN_BAND
- BLIND
- SECOND_ORDER

Use with:

```bat
py scripts/run_sqli_test_suite.py --suite test_suites/mega_sqli_debug_suite --email test3@test.com --password 123456
```

Or directly from ZIP:

```bat
py scripts/run_sqli_test_suite.py --suite test_suites/mega_sqli_debug_suite.zip --email test3@test.com --password 123456
```

Summary:
```json
{
  "py/SAFE/NONE": 8,
  "py/VULNERABLE/IN_BAND": 8,
  "py/VULNERABLE/BLIND": 2,
  "py/VULNERABLE/SECOND_ORDER": 2,
  "js/VULNERABLE/IN_BAND": 3,
  "js/SAFE/NONE": 3,
  "js/VULNERABLE/BLIND": 1,
  "js/VULNERABLE/SECOND_ORDER": 1,
  "java/VULNERABLE/IN_BAND": 2,
  "java/SAFE/NONE": 2,
  "java/VULNERABLE/BLIND": 1,
  "java/VULNERABLE/SECOND_ORDER": 1,
  "php/VULNERABLE/IN_BAND": 2,
  "php/SAFE/NONE": 2,
  "php/VULNERABLE/BLIND": 1,
  "php/VULNERABLE/SECOND_ORDER": 1
}
```
