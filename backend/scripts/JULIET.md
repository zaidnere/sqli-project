# Juliet Dataset Integration

The Juliet Test Suite is a collection of synthetic vulnerable programs
maintained by NIST. CWE-89 covers SQL Injection.

## Download

1. Go to: https://samate.nist.gov/SARD/test-suites/112
2. Download the Java version (Juliet_Test_Suite_v1.3_for_Java.zip)
3. Extract it — locate the `CWE89_SQL_Injection` folder inside

## Use with export_for_colab.py

```bash
# Generate training data WITH Juliet samples included:
python scripts/export_for_colab.py --juliet /path/to/CWE89_SQL_Injection/

# Example on Windows:
python scripts/export_for_colab.py --juliet C:\Downloads\juliet\CWE89_SQL_Injection\
```

The script will:
- Load up to 200 `*_bad*.java` files as vulnerable samples
- Load up to 200 `*_good*.java` files as safe samples
- Run all files through the full preprocessing pipeline
- Add them to the training dataset before augmentation

## Expected result

With Juliet included, dataset size grows from ~1,200 to ~1,600 samples.
The Juliet samples improve the model's ability to detect patterns in Java
and expose it to real-world vulnerability patterns from NIST.

## Without Juliet

The system works without Juliet. The 75 hand-crafted vulnerable samples and
75 safe samples (×8 augmentation = 1,200 total) provide a balanced dataset
covering Python, JavaScript, PHP, and Java patterns.
