# ML-only Suite Evaluation
- Suite: **ml_generalization_stress_suite_v1.zip**
- Model version: **model1-cnn-bilstm-dual-head-v20-attack-surface-ml95**
- Weights: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_model.npz`
- Metadata: `C:\Users\zaidn\OneDrive\Documents\final\sqli-project\backend\app\model\weights\sqli_detection_metadata.json`
- Threshold: **0.3600** from `metadata.threshold`
- Total: **80**
- Binary ML accuracy: **64/80** (80.00%)
- Full ML label+type accuracy: **57/80** (71.25%)
- Precision / Recall / F1: **0.8667 / 0.8667 / 0.8667**
- FP / FN: **8 / 8**
- Expected attack distribution: `{'NONE': 20, 'IN_BAND': 20, 'BLIND': 20, 'SECOND_ORDER': 20}`
- ML attack distribution: `{'NONE': 21, 'IN_BAND': 23, 'SECOND_ORDER': 17, 'BLIND': 19}`

## Failures

- `java/042_SAFE_stress_java.java` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `java/043_SAFE_stress_java.java` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.4067`
- `java/044_SAFE_stress_java.java` expected `SAFE / NONE` got `VULNERABLE / SECOND_ORDER` risk `0.9952`
- `java/054_BLIND_stress_java.java` expected `VULNERABLE / BLIND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `java/056_SECOND_ORDER_stress_java.java` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `javascript/026_IN_BAND_stress_js.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0564`
- `javascript/027_IN_BAND_stress_js.js` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0`
- `javascript/028_IN_BAND_stress_js.js` expected `VULNERABLE / IN_BAND` got `VULNERABLE / SECOND_ORDER` risk `1.0`
- `javascript/038_SECOND_ORDER_stress_js.js` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
- `php/067_IN_BAND_stress_php.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0`
- `php/069_IN_BAND_stress_php.php` expected `VULNERABLE / IN_BAND` got `SAFE / NONE` risk `0.0`
- `php/076_SECOND_ORDER_stress_php.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.0013`
- `php/077_SECOND_ORDER_stress_php.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.0`
- `php/078_SECOND_ORDER_stress_php.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.0001`
- `php/080_SECOND_ORDER_stress_php.php` expected `VULNERABLE / SECOND_ORDER` got `SAFE / NONE` risk `0.0003`
- `python/001_SAFE_stress_py.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `python/002_SAFE_stress_py.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `python/003_SAFE_stress_py.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `python/004_SAFE_stress_py.py` expected `SAFE / NONE` got `VULNERABLE / IN_BAND` risk `1.0`
- `python/005_SAFE_stress_py.py` expected `SAFE / NONE` got `VULNERABLE / NONE` risk `0.7091`
- `python/007_IN_BAND_stress_py.py` expected `VULNERABLE / IN_BAND` got `VULNERABLE / BLIND` risk `1.0`
- `python/014_BLIND_stress_py.py` expected `VULNERABLE / BLIND` got `VULNERABLE / IN_BAND` risk `1.0`
- `python/018_SECOND_ORDER_stress_py.py` expected `VULNERABLE / SECOND_ORDER` got `VULNERABLE / IN_BAND` risk `1.0`
