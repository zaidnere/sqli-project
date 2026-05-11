# FULL_PIPELINE_MODEL1_TO_MODEL2_RUNNER_MARKER
"""
Full direct pipeline runner for SQLi project suites.

What it does:
1) Reads existing detection suites from ZIP files containing manifest.csv.
2) Runs Model 1 detection through app.services.scan_service._build_detection.
3) If Model 1 routes the case as non-SAFE, sends Model 1's final attack type into Model 2.
4) Runs Model 2 fix recommendation and fix_generator rendering.
5) Compares:
   - Model 1 detection output vs suite expected verdict/type.
   - Model 2 output vs inferred fix type for vulnerable cases.
   - End-to-end system result.

Important:
- Existing detection suites do not contain explicit Model 2 A/B/C/D labels.
  For Model 2, expected fix type is inferred from expected attack type + code context.
- This script does not modify Model 1, Model 2, weights, suites, or source code.
- It writes outputs by test type and overwrites only its own output files.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import types
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Make the script runnable from backend without requiring PYTHONPATH=.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Lightweight stubs so importing scan_service does not require MongoDB/bson.
try:
    import bson  # type: ignore
except Exception:
    bson = types.ModuleType("bson")

    class ObjectId(str):
        pass

    bson.ObjectId = ObjectId
    sys.modules["bson"] = bson

if "app.db.database" not in sys.modules:
    m = types.ModuleType("app.db.database")
    m.get_audit_logs_collection = lambda: None
    sys.modules["app.db.database"] = m

if "app.services.audit_log_service" not in sys.modules:
    m2 = types.ModuleType("app.services.audit_log_service")

    async def log_audit_event(*args, **kwargs):
        return "local-full-pipeline-scan"

    m2.log_audit_event = log_audit_event
    sys.modules["app.services.audit_log_service"] = m2

from app.services.scan_service import _build_detection
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.fix_model_inference import run_fix_inference, fix_model_is_loaded
from app.fix_engine.fix_generator import generate_fix

DEFAULT_OUTPUT_PREFIX = "full_pipeline_model1_model2"


@dataclass
class PipelineCaseResult:
    suite: str
    source_zip: str
    file: str
    language: str

    expected_verdict: str
    expected_attack_type: str
    expected_fix_type: str
    expected_fix_reason: str

    model1_verdict: str
    model1_attack_type: str
    model1_pass: bool
    model1_label_pass: bool
    model1_type_pass: bool
    model1_risk_score: Any
    model1_ml_executed: Any
    model1_ml_risk_score: Any
    model1_ml_predicted_verdict: str
    model1_ml_predicted_attack_type: str
    model1_decision_source: str
    model1_verdict_source: str
    model1_fusion_reason: str

    model2_routed: bool
    model2_should_be_evaluated: bool
    model2_attack_type_input: str
    model2_model_fix_type: str
    model2_final_fix_type: str
    model2_model_pass: bool
    model2_final_pass: bool
    model2_content_pass: bool
    model2_confidence: Any
    model2_probabilities: Any

    full_system_pass: bool
    failure_stage: str
    crashed: bool
    error: str
    fixed_code_preview: str


def _safe_name(value: str) -> str:
    value = (value or "all").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    return value.strip("_") or "all"


def _decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1255", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _find_manifest(zf: zipfile.ZipFile) -> str | None:
    manifests = [n for n in zf.namelist() if n.lower().endswith("manifest.csv")]
    if not manifests:
        return None
    return sorted(manifests, key=lambda x: (x.count("/"), len(x)))[0]


def _norm_type(value: str | None) -> str:
    return (value or "NONE").strip().upper().replace("-", "_").replace(" ", "_") or "NONE"


def _norm_verdict(value: str | None) -> str:
    v = (value or "").strip().upper()
    if v in {"", "NONE", "CLEAN"}:
        return "SAFE"
    return v


def _g(obj: Any, name: str, default: Any = "") -> Any:
    return getattr(obj, name, default)


def _infer_language(row: dict[str, str], file_path: str) -> str:
    lang = (row.get("language") or "").strip().lower()
    if lang:
        return lang
    ext = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".java": "java",
        ".php": "php",
    }.get(ext, "unknown")


def _strip_comments(code: str, language: str) -> str:
    if language == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _detect_identifier_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    order_by = _rx(
        r"\bORDER\s+BY\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )
    table_name = _rx(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )
    return bool(order_by or table_name)


def _detect_complex_builder_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    loop_builder = _rx(
        r"\b(?:for|foreach)\b[\s\S]{0,220}(?:filters|criteria|whereMap|searchFields|params|Object\.keys|keySet|items\s*\(|implode|join)",
        c,
    ) and _rx(
        r"(?:sql|query|where|parts|where_parts)[\s\S]{0,260}(?:\+=|\.=|\.append\s*\(|\.push\s*\(|\.add\s*\(|join\s*\(|implode\s*\()",
        c,
    )
    helper_builder = _rx(
        r"\b(?:build|make|compose|create|assemble|render)[A-Za-z0-9_]*(?:sql|query|where|filter|search|report)[A-Za-z0-9_]*\s*\(",
        c,
    )
    querybuilder_name = _rx(r"\b(?:QueryBuilder|queryBuilder|criteriaBuilder|createQueryBuilder|knex|sequelize|sqlalchemy)\b", c)
    dynamic_where_parts = _rx(r"(?:where_parts|parts|clauses|conditions)\s*=\s*\[", c) and _rx(r"\.join\s*\(|implode\s*\(", c)
    return bool(loop_builder or helper_builder or querybuilder_name or dynamic_where_parts)


def _infer_expected_fix(expected_type: str, code: str, language: str, row: dict[str, str]) -> tuple[str, str]:
    """Infer Model 2 expected label from detection-suite context.

    Detection suites do not have true A/B/C/D fix labels. This inference is only
    for stress/regression testing and must be reviewed before being used as
    training truth.
    """
    t = _norm_type(expected_type)
    category = " ".join(str(row.get(k, "")) for k in ("category", "focus_area", "description", "notes")).lower()

    if t == "SECOND_ORDER":
        return "D", "expected attack type is SECOND_ORDER"
    if any(x in category for x in ("second_order", "second-order", "stored sql", "saved filter")):
        return "D", "manifest describes stored/second-order SQL fragment"
    if any(x in category for x in ("query builder", "builder", "orm", "criteria", "dynamic where", "filters")):
        return "C", "manifest describes complex builder/ORM-style case"
    if _detect_complex_builder_context(code, language):
        return "C", "code contains complex dynamic query-builder/helper context"
    if _detect_identifier_context(code, language):
        return "B", "code contains dynamic SQL identifier context (ORDER BY/table name)"
    return "A", "default vulnerable value-injection repair is parameterized query"


def _content_check(expected_fix: str, fixed_code: str) -> bool:
    text = fixed_code or ""
    lower = text.lower()
    if expected_fix == "A":
        return ("?" in text or "prepare" in lower or "parameterized" in lower or "bound" in lower) and not (
            "allowed_columns" in lower or "allowedtables" in lower
        )
    if expected_fix == "B":
        return "allowed" in lower or "whitelist" in lower or "allowlist" in lower
    if expected_fix == "C":
        return "orm" in lower or "query builder" in lower or "builder" in lower
    if expected_fix == "D":
        return "second" in lower or "stored" in lower or "trusted" in lower or "static template" in lower
    return False


def _read_manifest_rows(zip_path: Path) -> tuple[list[dict[str, str]], str, str]:
    with zipfile.ZipFile(zip_path) as zf:
        manifest_name = _find_manifest(zf)
        if not manifest_name:
            raise ValueError(f"manifest.csv not found in {zip_path}")
        text = _decode_bytes(zf.read(manifest_name))
        rows = list(csv.DictReader(text.splitlines()))
        root = manifest_name.rsplit("/", 1)[0] if "/" in manifest_name else ""
        return rows, manifest_name, root


def _read_code_from_zip(zip_path: Path, root: str, rel_file: str) -> str:
    rel_file = rel_file.replace("\\", "/")
    candidates: list[str] = []
    if root:
        candidates.append(f"{root}/{rel_file}")
    candidates.append(rel_file)
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        for name in candidates:
            if name in names:
                return _decode_bytes(zf.read(name))
        matches = [n for n in names if n.endswith("/" + rel_file) or n == rel_file]
        if matches:
            return _decode_bytes(zf.read(sorted(matches, key=len)[0]))
    raise FileNotFoundError(f"{rel_file} not found in {zip_path}")


def _zip_has_manifest(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return _find_manifest(zf) is not None
    except Exception:
        return False


def _discover_suites(args: argparse.Namespace) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    if args.suite:
        paths.extend(Path(p) for p in args.suite)
    if args.suites:
        paths.extend(Path(p) for p in args.suites)
    if args.dir:
        base = Path(args.dir)
        if base.exists():
            paths.extend(sorted(base.glob(args.pattern)))

    out: list[Path] = []
    skipped: list[str] = []
    seen = set()
    for p in paths:
        if not p.exists() or not p.is_file() or p.suffix.lower() != ".zip":
            continue
        if p.name == "model2_fix_cases.zip":
            skipped.append(f"{p}: skipped model2 fix suite zip")
            continue
        if not _zip_has_manifest(p):
            skipped.append(f"{p}: skipped because manifest.csv was not found")
            continue
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            out.append(p)
    if args.only:
        needles = [_safe_name(x) for x in args.only]
        out = [p for p in out if any(n in _safe_name(p.stem) for n in needles)]
    return out, skipped


def _failure_stage(expected_v: str, model1_pass: bool, model2_should: bool, model2_model_pass: bool, final_pass: bool, content_pass: bool, crashed: bool) -> str:
    if crashed:
        return "crash"
    if not model1_pass:
        return "model1_detection"
    if expected_v == "SAFE":
        return "none" if model1_pass else "model1_detection"
    if model2_should and not model2_model_pass:
        return "model2_fix_classification"
    if model2_should and not final_pass:
        return "fix_generator_final_type"
    if model2_should and not content_pass:
        return "fix_generator_content"
    return "none"


def _run_case(zip_path: Path, suite_name: str, root: str, row: dict[str, str], vocab: dict[str, int], force_ml: bool = False) -> PipelineCaseResult:
    rel_file = (row.get("file") or row.get("path") or row.get("filename") or "").strip()
    language = _infer_language(row, rel_file)
    expected_verdict = _norm_verdict(row.get("expected_verdict") or row.get("expected_label") or row.get("label") or "")
    expected_type = _norm_type(row.get("expected_type") or row.get("expected_attack_type") or row.get("attack_type") or "NONE")

    empty = {
        "expected_fix_type": "NONE",
        "expected_fix_reason": "SAFE/NONE case does not require Model 2 fix recommendation",
        "model2_routed": False,
        "model2_should_be_evaluated": False,
        "model2_attack_type_input": "",
        "model2_model_fix_type": "",
        "model2_final_fix_type": "",
        "model2_model_pass": True,
        "model2_final_pass": True,
        "model2_content_pass": True,
        "model2_confidence": "",
        "model2_probabilities": "",
        "fixed_code_preview": "",
    }

    try:
        code = _read_code_from_zip(zip_path, root, rel_file)
        det = _build_detection(code, language, force_ml=force_ml)
        model1_verdict = _norm_verdict(_g(det, "label"))
        model1_type = _norm_type(_g(det, "attackType") if model1_verdict != "SAFE" else "NONE")
        model1_label_pass = model1_verdict == expected_verdict
        model1_type_pass = expected_verdict == "SAFE" or model1_type == expected_type
        model1_pass = model1_label_pass and model1_type_pass

        # Real system routing: Model 2 receives Model 1's final output.
        model2_routed = model1_verdict != "SAFE"
        model2_should_eval = expected_verdict != "SAFE" and model2_routed

        expected_fix = "NONE"
        expected_reason = "SAFE/NONE case does not require Model 2 fix recommendation"
        pred: dict[str, Any] = {}
        final_fix = ""
        model_fix = ""
        fixed_code = ""
        model_pass = True
        final_pass = True
        content_pass = True

        if expected_verdict != "SAFE":
            expected_fix, expected_reason = _infer_expected_fix(expected_type, code, language, row)
            # If Model 1 missed the vulnerability, Model 2 would not run in the real pipeline.
            model_pass = False
            final_pass = False
            content_pass = False

        if model2_routed:
            cleaned = clean_code(code)
            tokens = tokenize_code(cleaned)
            normalized = normalize_tokens(tokens)
            vec = vectorize_tokens(normalized, vocab)
            pred = run_fix_inference(
                vec["tokenIds"],
                language=language,
                attack_type=model1_type,
                normalized_tokens=normalized,
                raw_code=code,
            ) or {}
            model_fix = (pred.get("fixType") or "").upper()
            fix = generate_fix(
                code,
                language,
                normalized,
                preferred_fix_type=model_fix,
                model_prediction=pred,
            )
            final_fix = (getattr(fix, "fix_type", "") or "").upper()
            fixed_code = getattr(fix, "fixed_code", "") or ""
            if expected_verdict != "SAFE":
                model_pass = model_fix == expected_fix
                final_pass = final_fix == expected_fix
                content_pass = _content_check(expected_fix, fixed_code)
            else:
                # False-positive route: Model 1 decides vulnerable on expected SAFE, full system should fail.
                model_pass = True
                final_pass = True
                content_pass = True

        full_pass = False
        if expected_verdict == "SAFE":
            full_pass = model1_pass
        else:
            full_pass = model1_pass and model2_should_eval and model_pass and final_pass and content_pass

        stage = _failure_stage(expected_verdict, model1_pass, model2_should_eval, model_pass, final_pass, content_pass, False)
        return PipelineCaseResult(
            suite=suite_name,
            source_zip=zip_path.name,
            file=rel_file,
            language=language,
            expected_verdict=expected_verdict,
            expected_attack_type=expected_type,
            expected_fix_type=expected_fix,
            expected_fix_reason=expected_reason,
            model1_verdict=model1_verdict,
            model1_attack_type=model1_type,
            model1_pass=model1_pass,
            model1_label_pass=model1_label_pass,
            model1_type_pass=model1_type_pass,
            model1_risk_score=_g(det, "riskScore"),
            model1_ml_executed=_g(det, "mlExecuted"),
            model1_ml_risk_score=_g(det, "mlRiskScore"),
            model1_ml_predicted_verdict=_norm_verdict(_g(det, "mlPredictedVerdict")) if _g(det, "mlPredictedVerdict") else "",
            model1_ml_predicted_attack_type=_norm_type(_g(det, "mlPredictedAttackType")) if _g(det, "mlPredictedAttackType") else "",
            model1_decision_source=str(_g(det, "decisionSource")),
            model1_verdict_source=str(_g(det, "verdictSource")),
            model1_fusion_reason=str(_g(det, "fusionReason")),
            model2_routed=model2_routed,
            model2_should_be_evaluated=model2_should_eval,
            model2_attack_type_input=model1_type if model2_routed else "",
            model2_model_fix_type=model_fix,
            model2_final_fix_type=final_fix,
            model2_model_pass=model_pass,
            model2_final_pass=final_pass,
            model2_content_pass=content_pass,
            model2_confidence=pred.get("confidence", ""),
            model2_probabilities=json.dumps(pred.get("allProbabilities", {}), ensure_ascii=False),
            full_system_pass=full_pass,
            failure_stage=stage,
            crashed=False,
            error="",
            fixed_code_preview=fixed_code.replace("\r", "").replace("\n", "\\n")[:500],
        )
    except Exception as exc:
        return PipelineCaseResult(
            suite=suite_name,
            source_zip=zip_path.name,
            file=rel_file,
            language=language,
            expected_verdict=expected_verdict,
            expected_attack_type=expected_type,
            expected_fix_type=empty["expected_fix_type"],
            expected_fix_reason=empty["expected_fix_reason"],
            model1_verdict="",
            model1_attack_type="",
            model1_pass=False,
            model1_label_pass=False,
            model1_type_pass=False,
            model1_risk_score="",
            model1_ml_executed="",
            model1_ml_risk_score="",
            model1_ml_predicted_verdict="",
            model1_ml_predicted_attack_type="",
            model1_decision_source="",
            model1_verdict_source="",
            model1_fusion_reason="",
            model2_routed=False,
            model2_should_be_evaluated=False,
            model2_attack_type_input="",
            model2_model_fix_type="",
            model2_final_fix_type="",
            model2_model_pass=False,
            model2_final_pass=False,
            model2_content_pass=False,
            model2_confidence="",
            model2_probabilities="",
            full_system_pass=False,
            failure_stage="crash",
            crashed=True,
            error=repr(exc),
            fixed_code_preview="",
        )


def _percent(n: int, d: int) -> float:
    return round((100.0 * n / d), 2) if d else 0.0


def _summarize(results: list[PipelineCaseResult], suites: list[Path], skipped_zips: list[str], csv_path: str, json_path: str) -> dict[str, Any]:
    total = len(results)
    expected_vulnerable = [r for r in results if r.expected_verdict != "SAFE"]
    expected_safe = [r for r in results if r.expected_verdict == "SAFE"]
    model2_eval = [r for r in results if r.model2_should_be_evaluated]

    by_suite: dict[str, Any] = {}
    for suite in sorted({r.suite for r in results}):
        items = [r for r in results if r.suite == suite]
        suite_vuln = [r for r in items if r.expected_verdict != "SAFE"]
        suite_model2 = [r for r in items if r.model2_should_be_evaluated]
        by_suite[suite] = {
            "totalRows": len(items),
            "expectedSafe": sum(1 for r in items if r.expected_verdict == "SAFE"),
            "expectedVulnerable": len(suite_vuln),
            "model1Passed": sum(1 for r in items if r.model1_pass),
            "model1Failed": sum(1 for r in items if not r.model1_pass),
            "model2Routed": sum(1 for r in items if r.model2_routed),
            "model2Evaluated": len(suite_model2),
            "model2ModelPassed": sum(1 for r in suite_model2 if r.model2_model_pass),
            "model2FinalPassed": sum(1 for r in suite_model2 if r.model2_final_pass),
            "model2ContentPassed": sum(1 for r in suite_model2 if r.model2_content_pass),
            "fullSystemPassed": sum(1 for r in items if r.full_system_pass),
            "fullSystemFailed": sum(1 for r in items if not r.full_system_pass),
            "crashedCases": sum(1 for r in items if r.crashed),
        }

    failure_stages: dict[str, int] = {}
    for r in results:
        failure_stages[r.failure_stage] = failure_stages.get(r.failure_stage, 0) + (0 if r.failure_stage == "none" else 1)
    failure_stages = {k: v for k, v in failure_stages.items() if v}

    model1_pass = sum(1 for r in results if r.model1_pass)
    full_pass = sum(1 for r in results if r.full_system_pass)
    model2_model_pass = sum(1 for r in model2_eval if r.model2_model_pass)
    model2_final_pass = sum(1 for r in model2_eval if r.model2_final_pass)
    model2_content_pass = sum(1 for r in model2_eval if r.model2_content_pass)

    return {
        "suite": "full_pipeline_model1_to_model2_v1",
        "note": "Runs Model 1 first, then routes Model 1 final output into Model 2. Model 2 labels are inferred for detection suites because those suites do not contain explicit fix labels.",
        "sourceSuites": [p.name for p in suites],
        "skippedZipFiles": skipped_zips,
        "totalRows": total,
        "expectedSafe": len(expected_safe),
        "expectedVulnerable": len(expected_vulnerable),
        "model1DetectionPassed": model1_pass,
        "model1DetectionFailed": total - model1_pass,
        "model1DetectionAccuracyPct": _percent(model1_pass, total),
        "model2RoutedByModel1": sum(1 for r in results if r.model2_routed),
        "model2EvaluatedExpectedVulnerable": len(model2_eval),
        "model2ModelFixPassed": model2_model_pass,
        "model2ModelFixFailed": len(model2_eval) - model2_model_pass,
        "model2ModelFixAccuracyPct": _percent(model2_model_pass, len(model2_eval)),
        "model2FinalFixPassed": model2_final_pass,
        "model2FinalFixFailed": len(model2_eval) - model2_final_pass,
        "model2FinalFixAccuracyPct": _percent(model2_final_pass, len(model2_eval)),
        "model2ContentPassed": model2_content_pass,
        "model2ContentFailed": len(model2_eval) - model2_content_pass,
        "model2ContentAccuracyPct": _percent(model2_content_pass, len(model2_eval)),
        "fullPipelinePassed": full_pass,
        "fullPipelineFailed": total - full_pass,
        "fullPipelineAccuracyPct": _percent(full_pass, total),
        "vulnerableEndToEndPassed": sum(1 for r in expected_vulnerable if r.full_system_pass),
        "vulnerableEndToEndFailed": len(expected_vulnerable) - sum(1 for r in expected_vulnerable if r.full_system_pass),
        "vulnerableEndToEndAccuracyPct": _percent(sum(1 for r in expected_vulnerable if r.full_system_pass), len(expected_vulnerable)),
        "crashedCases": sum(1 for r in results if r.crashed),
        "model2ModelFixTypeCounts": {k: sum(1 for r in model2_eval if r.model2_model_fix_type == k) for k in ["A", "B", "C", "D", ""]},
        "model2FinalFixTypeCounts": {k: sum(1 for r in model2_eval if r.model2_final_fix_type == k) for k in ["A", "B", "C", "D", ""]},
        "failureStages": failure_stages,
        "bySuite": by_suite,
        "csv": csv_path,
        "json": json_path,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", action="append", help="Specific detection suite ZIP. Can be repeated.")
    ap.add_argument("--suites", nargs="*", help="List of detection suite ZIP files.")
    ap.add_argument("--dir", default="test_suites_model2_detection", help="Directory to scan for ZIP suites.")
    ap.add_argument("--pattern", default="*.zip", help="Glob pattern inside --dir.")
    ap.add_argument("--only", action="append", help="Run only suite names containing this substring. Can be repeated.")
    ap.add_argument("--output-name", default="", help="Output basename without extension. Default is based on --only/all.")
    ap.add_argument("--csv", default="", help="Override CSV output path.")
    ap.add_argument("--json", default="", help="Override JSON output path.")
    ap.add_argument("--force-ml", action="store_true", help="Pass force_ml=True into Model 1 detection for diagnostics.")
    args = ap.parse_args()

    if not fix_model_is_loaded():
        raise SystemExit("ERROR: Model 2 or shared Model 1 embedding did not load.")

    suites, skipped_zips = _discover_suites(args)
    if not suites:
        raise SystemExit("ERROR: No valid detection suite ZIPs found. Put them under test_suites_model2_detection or pass --suite.")

    out_tag = _safe_name(args.output_name or ("_".join(args.only) if args.only else "all_detection_suites"))
    out_dir = Path("outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.csv or str(out_dir / f"{DEFAULT_OUTPUT_PREFIX}_{out_tag}_results.csv")
    json_path = args.json or str(out_dir / f"{DEFAULT_OUTPUT_PREFIX}_{out_tag}_summary.json")

    vocab = build_fixed_vocabulary()
    results: list[PipelineCaseResult] = []
    for suite_zip in suites:
        rows, _manifest_name, root = _read_manifest_rows(suite_zip)
        suite_name = suite_zip.stem
        for row in rows:
            results.append(_run_case(suite_zip, suite_name, root, row, vocab, force_ml=args.force_ml))

    fields = list(PipelineCaseResult.__dataclass_fields__.keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    summary = _summarize(results, suites, skipped_zips, csv_path, json_path)
    Path(json_path).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Full Pipeline Model1 → Model2 Direct V1")
    print("----------------------------------------")
    print(f"Suites:                         {len(suites)}")
    print(f"Total rows:                     {summary['totalRows']}")
    print(f"Expected SAFE:                  {summary['expectedSafe']}")
    print(f"Expected vulnerable:            {summary['expectedVulnerable']}")
    print(f"Model 1 detection:              {summary['model1DetectionPassed']}/{summary['totalRows']} ({summary['model1DetectionAccuracyPct']}%)")
    print(f"Model 2 evaluated:              {summary['model2EvaluatedExpectedVulnerable']}")
    print(f"Model 2 model fix:              {summary['model2ModelFixPassed']}/{summary['model2EvaluatedExpectedVulnerable']} ({summary['model2ModelFixAccuracyPct']}%)")
    print(f"Model 2 final fix:              {summary['model2FinalFixPassed']}/{summary['model2EvaluatedExpectedVulnerable']} ({summary['model2FinalFixAccuracyPct']}%)")
    print(f"Model 2 content:                {summary['model2ContentPassed']}/{summary['model2EvaluatedExpectedVulnerable']} ({summary['model2ContentAccuracyPct']}%)")
    print(f"Vulnerable end-to-end:          {summary['vulnerableEndToEndPassed']}/{summary['expectedVulnerable']} ({summary['vulnerableEndToEndAccuracyPct']}%)")
    print(f"Full pipeline overall:          {summary['fullPipelinePassed']}/{summary['totalRows']} ({summary['fullPipelineAccuracyPct']}%)")
    print(f"Crashed cases:                  {summary['crashedCases']}")
    if skipped_zips:
        print(f"Skipped non-suite ZIPs:         {len(skipped_zips)}")
    print(f"CSV:                            {csv_path}")
    print(f"JSON:                           {json_path}")
    return 0 if summary["fullPipelineFailed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
