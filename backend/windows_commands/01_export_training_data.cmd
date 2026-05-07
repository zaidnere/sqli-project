@echo off
REM Run from backend\
set PYTHONPATH=.
python scripts\export_for_colab.py ^
  --out colab_export ^
  --sequence-length 256 ^
  --generated-per-class 4 ^
  --hardcase-per-family 10 ^
  --safe-calibration-per-family 5 ^
  --generated-seeds 20260531 20260601 20260602 ^
  --audit-csv outputs\model_audit_mega_after_v8.csv ^
  --audit-csv outputs\model_audit_realistic_after_v8.csv ^
  --audit-csv outputs\model_audit_framework_after_v8.csv ^
  --audit-csv outputs\model_audit_enterprise_after_v8.csv ^
  --audit-csv outputs\model_audit_hard_after_v8.csv ^
  --audit-csv outputs\model_audit_targeted_after_v8.csv
