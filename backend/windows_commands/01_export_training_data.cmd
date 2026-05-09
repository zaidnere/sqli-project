@echo off
set PYTHONPATH=.
python scripts\export_for_colab.py ^
  --out colab_export ^
  --sequence-length 256 ^
  --generated-per-class 4 ^
  --hardcase-per-family 18 ^
  --safe-calibration-per-family 10 ^
  --generated-seeds 20260910 20260911 20260912 ^
  --audit-csv outputs\v14_policy_realistic.csv ^
  --audit-csv outputs\v14_policy_enterprise.csv ^
  --audit-csv outputs\v14_policy_framework.csv ^
  --audit-csv outputs\v14_policy_adversarial.csv ^
  --audit-csv outputs\model_audit_enterprise_after_v17b.csv ^
  --audit-csv outputs\model_audit_adversarial_after_v17b.csv ^
  --audit-csv outputs\model_audit_framework_after_v17b.csv
