# ML-only Suite Evaluation
- Suite: **unseen_generalization_suite_latest_fixed.zip**
- Model version: **model1-cnn-bilstm-dual-head-v18-ml95-binary**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.5200** from `metadata.threshold`
- Total: **128**
- Binary ML accuracy: **126/128** (98.44%)
- Full ML label+type accuracy: **110/128** (85.94%)
- Precision / Recall / F1: **0.9796 / 1.0000 / 0.9897**
- FP / FN: **2 / 0**
- Expected attack distribution: `{'NONE': 32, 'IN_BAND': 32, 'BLIND': 32, 'SECOND_ORDER': 32}`
- ML attack distribution: `{'NONE': 30, 'IN_BAND': 41, 'BLIND': 24, 'SECOND_ORDER': 33}`

## Failures

- `javascript/034_SAFE_unseen_case_bnagwhn.js` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.8126`
- `javascript/039_SAFE_unseen_case_xsccfhj.js` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `0.9544`
- `php/121_SECOND_ORDER_unseen_case_lexrhyc.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/122_SECOND_ORDER_unseen_case_omrxhis.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/123_SECOND_ORDER_unseen_case_rkjondg.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/124_SECOND_ORDER_unseen_case_vyblmyh.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/125_SECOND_ORDER_unseen_case_phhiwve.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/126_SECOND_ORDER_unseen_case_zouwsvk.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/127_SECOND_ORDER_unseen_case_dvzbrpi.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `php/128_SECOND_ORDER_unseen_case_mmjsrbp.php` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `0.994`
- `python/017_BLIND_unseen_case_squfjnn.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/018_BLIND_unseen_case_kzgvxjt.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/019_BLIND_unseen_case_zfrorax.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/020_BLIND_unseen_case_xxctxye.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/021_BLIND_unseen_case_pthokup.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/022_BLIND_unseen_case_wukqdcs.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/023_BLIND_unseen_case_npfpqgp.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `python/024_BLIND_unseen_case_upvkhha.py` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
