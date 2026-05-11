# ML-only Full Suite Comparison

This compares the current deployed ML-only weights against the previous baseline metrics files.

| Suite | Total | Current binary | Baseline binary | Δ binary | Current full | Baseline full | Δ full | FP current/base | FN current/base |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| targeted_next_debug_suite | 32 | 90.62% | 75.00% | +15.62pp | 90.62% |  |  | 3/None | 0/None |
| mega_sqli_debug_suite | 40 | 97.50% |  |  | 95.00% |  |  | 1/None | 0/None |
| realistic_long_sqli_suite | 18 | 83.33% |  |  | 77.78% |  |  | 2/None | 1/None |
| enterprise_realistic_sqli_final_suite | 40 | 80.00% | 77.50% | +2.50pp | 70.00% |  |  | 3/None | 5/None |
| final_framework_obfuscation_stability_suite | 64 | 76.56% | 81.25% | -4.69pp | 65.62% |  |  | 10/None | 5/None |
| adversarial_real_world_sqli_challenge_suite | 32 | 75.00% | 75.00% | +0.00pp | 68.75% |  |  | 6/None | 2/None |
| v18_remaining_edge_focused_suite | 28 | 89.29% | 67.86% | +21.43pp | 85.71% |  |  | 0/None | 3/None |
| v18_provenance_overfit_guard_suite | 20 | 75.00% |  |  | 70.00% |  |  | 2/None | 3/None |
| unseen_generalization_suite_latest_fixed | 128 | 100.00% | 100.00% | +0.00pp | 87.50% |  |  | 0/None | 0/None |
| hard_mixed_sqli_challenge_suite | 80 | 96.25% |  |  | 90.00% |  |  | 1/None | 2/None |
| known_good_sqli_detection_suite | 40 | 85.00% |  |  | 77.50% |  |  | 6/None | 0/None |
| root_cause_attack_type_diagnostic_suite | 32 | 81.25% |  |  | 68.75% |  |  | 5/None | 1/None |
| stable_expected_detection_suite | 40 | 87.50% |  |  | 75.00% |  |  | 4/None | 1/None |
| **TOTAL** | **594** | **88.89%** | **46.80%** | **+42.09pp** | **80.47%** | **0.00%** | **+80.47pp** | **43/0** | **23/0** |
