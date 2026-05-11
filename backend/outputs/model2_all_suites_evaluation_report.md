# Model 2 All-Suites Evaluation Report

This report consolidates the language-aware fix-generator regression, dedicated Model 2 fix suites, and full pipeline strict evaluation using official Model 1 outputs.

## Full Pipeline Strict
- Model 1 official: 594/594 (100.0%)
- Model 2 classification: 382/385 (99.22%)
- Model 2 final fix type: 382/385 (99.22%)
- Strict generated-fix validation: 382/385 (99.22%)
- Full pipeline strict: 591/594 (99.49%)

## Fix Generator Language Regression
- Passed: 6/6 (100.0%)

## Failure Review
- Total failures: 3
- By stage: `{"model2_fix_classification": 3}`
- By language: `{"python": 2, "javascript": 1}`
- Failure CSV: `outputs\model2_all_suites_failure_review.csv`
