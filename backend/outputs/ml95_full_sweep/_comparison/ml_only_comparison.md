# ML-only Full Suite Comparison

This compares the current deployed ML-only weights against the previous baseline metrics files.

| Suite | Total | Current binary | Baseline binary | Δ binary | Current full | Baseline full | Δ full | FP current/base | FN current/base |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| targeted_next_debug_suite | 32 | 62.50% |  |  | 56.25% |  |  | 11/None | 1/None |
| mega_sqli_debug_suite | 40 | 75.00% |  |  | 62.50% |  |  | 9/None | 1/None |
| realistic_long_sqli_suite | 18 | 72.22% |  |  | 38.89% |  |  | 5/None | 0/None |
| enterprise_realistic_sqli_final_suite | 40 | 70.00% |  |  | 30.00% |  |  | 12/None | 0/None |
| final_framework_obfuscation_stability_suite | 64 | 50.00% |  |  | 28.12% |  |  | 32/None | 0/None |
| adversarial_real_world_sqli_challenge_suite | 32 | 62.50% |  |  | 25.00% |  |  | 12/None | 0/None |
| v18_remaining_edge_focused_suite | 28 | 57.14% |  |  | 25.00% |  |  | 12/None | 0/None |
| v18_provenance_overfit_guard_suite | 20 | 65.00% |  |  | 25.00% |  |  | 7/None | 0/None |
| unseen_generalization_suite_latest_fixed | 128 | 98.44% |  |  | 85.94% |  |  | 2/None | 0/None |
| hard_mixed_sqli_challenge_suite | 80 | 78.75% |  |  | 55.00% |  |  | 11/None | 6/None |
| known_good_sqli_detection_suite | 40 | 62.50% |  |  | 40.00% |  |  | 15/None | 0/None |
| root_cause_attack_type_diagnostic_suite | 32 | 71.88% |  |  | 43.75% |  |  | 9/None | 0/None |
| stable_expected_detection_suite | 40 | 55.00% |  |  | 32.50% |  |  | 18/None | 0/None |
| **TOTAL** | **594** | **72.56%** | **0.00%** | **+72.56pp** | **50.00%** | **0.00%** | **+50.00pp** | **155/0** | **8/0** |
