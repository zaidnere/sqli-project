@echo off
REM Run from backend\ after copying the V9 artifacts into app\model\weights
set PYTHONPATH=.
python scripts\run_local_detector_suite_direct.py --suite test_suites\targeted_next_debug_suite.zip --audit --force-ml --audit-csv outputs\model_audit_targeted_after_v9.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\mega_sqli_debug_suite.zip --audit --force-ml --audit-csv outputs\model_audit_mega_after_v9.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\realistic_long_sqli_suite.zip --audit --force-ml --audit-csv outputs\model_audit_realistic_after_v9.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\enterprise_realistic_sqli_final_suite.zip --audit --force-ml --audit-csv outputs\model_audit_enterprise_after_v9.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\hard_mixed_sqli_challenge_suite.zip --audit --force-ml --audit-csv outputs\model_audit_hard_after_v9.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\final_framework_obfuscation_stability_suite.zip --audit --force-ml --audit-csv outputs\model_audit_framework_after_v9.csv
