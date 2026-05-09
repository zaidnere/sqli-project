@echo off
cd /d %~dp0\..\backend
set PYTHONPATH=.
python scripts\run_local_detector_suite_direct.py --suite test_suites\enterprise_realistic_sqli_final_suite.zip --audit --audit-csv outputs\model_audit_enterprise_after_v17.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\adversarial_real_world_sqli_challenge_suite.zip --audit --audit-csv outputs\model_audit_adversarial_after_v17.csv
python scripts\run_local_detector_suite_direct.py --suite test_suites\final_framework_obfuscation_stability_suite.zip --audit --audit-csv outputs\model_audit_framework_after_v17.csv
