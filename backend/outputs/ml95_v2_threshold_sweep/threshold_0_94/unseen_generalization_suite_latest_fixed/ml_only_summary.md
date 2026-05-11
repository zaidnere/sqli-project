# ML-only Suite Evaluation
- Suite: **unseen_generalization_suite_latest_fixed.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.9400** from `cli`
- Total: **128**
- Binary ML accuracy: **128/128** (100.00%)
- Full ML label+type accuracy: **112/128** (87.50%)
- Precision / Recall / F1: **1.0000 / 1.0000 / 1.0000**
- FP / FN: **0 / 0**
- Expected attack distribution: `{'NONE': 32, 'IN_BAND': 32, 'BLIND': 32, 'SECOND_ORDER': 32}`
- ML attack distribution: `{'NONE': 32, 'IN_BAND': 48, 'BLIND': 24, 'SECOND_ORDER': 24}`

## Failures

- `javascript/057_SECOND_ORDER_unseen_case_alzqjlu.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/058_SECOND_ORDER_unseen_case_meohdur.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/059_SECOND_ORDER_unseen_case_kobvehh.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/060_SECOND_ORDER_unseen_case_suousbr.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/061_SECOND_ORDER_unseen_case_vacijng.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/062_SECOND_ORDER_unseen_case_vjafclp.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/063_SECOND_ORDER_unseen_case_hkdabmm.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/064_SECOND_ORDER_unseen_case_ahzzczv.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `php/113_BLIND_unseen_case_feckgmb.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/114_BLIND_unseen_case_cxdaobq.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/115_BLIND_unseen_case_yfuzqzz.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/116_BLIND_unseen_case_byhsayx.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/117_BLIND_unseen_case_euvpwoq.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/118_BLIND_unseen_case_fqsyywl.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/119_BLIND_unseen_case_tvapbfk.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
- `php/120_BLIND_unseen_case_ztkdkie.php` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `0.9717`
