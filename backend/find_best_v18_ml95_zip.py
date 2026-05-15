from __future__ import annotations

import csv
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

KEYWORDS = [
    "model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer",
    "v18-ml95-v2-normalizer",
    "semantic-normalizer-v18-ml95-v2-safe-dynamic-sql",
    '"threshold": 0.96',
    '"threshold":0.96',
    "threshold= 0.96",
]

TEXT_SUFFIXES = {
    ".json", ".txt", ".md", ".csv", ".log", ".py", ".ipynb", ".yaml", ".yml"
}

MODEL_FILE_NAMES = {
    "sqli_model.npz",
    "sqli_detection_model.npz",
    "sqli_detection_metadata.json",
    "sqli_detection_metrics.json",
    "sqli_detection_vocab.json",
    "sqli_detection_label_maps.json",
    "training_history.json",
    "dataset_profile.json",
    "split_info.json",
}


def safe_decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1255", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def try_parse_json(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def search_zip(zip_path: Path) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    present_model_files: set[str] = set()
    metadata_candidates: list[dict[str, Any]] = []

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            names = z.namelist()

            for name in names:
                base_name = Path(name).name
                if base_name in MODEL_FILE_NAMES:
                    present_model_files.add(base_name)

                suffix = Path(name).suffix.lower()
                if suffix not in TEXT_SUFFIXES:
                    continue

                # Avoid giant files.
                info = z.getinfo(name)
                if info.file_size > 15_000_000:
                    continue

                try:
                    raw = z.read(name)
                except Exception:
                    continue

                text = safe_decode(raw)
                lowered = text.lower()

                for kw in KEYWORDS:
                    if kw.lower() in lowered:
                        hits.append({
                            "zip": str(zip_path),
                            "file_inside_zip": name,
                            "keyword": kw,
                        })

                if base_name.lower() == "sqli_detection_metadata.json" or "metadata" in base_name.lower():
                    obj = try_parse_json(text)
                    if obj:
                        metadata_candidates.append({
                            "file_inside_zip": name,
                            "model_version": obj.get("model_version"),
                            "threshold": obj.get("threshold"),
                            "selected_threshold": obj.get("selected_threshold"),
                            "normalizer_version": obj.get("normalizer_version"),
                            "training_date_utc": obj.get("training_date_utc"),
                            "vocabulary_sha256": obj.get("vocabulary_sha256"),
                        })

    except zipfile.BadZipFile:
        return {
            "zip": str(zip_path),
            "error": "BadZipFile",
            "hits": [],
            "present_model_files": [],
            "metadata_candidates": [],
        }
    except Exception as e:
        return {
            "zip": str(zip_path),
            "error": repr(e),
            "hits": [],
            "present_model_files": [],
            "metadata_candidates": [],
        }

    return {
        "zip": str(zip_path),
        "error": "",
        "hits": hits,
        "present_model_files": sorted(present_model_files),
        "metadata_candidates": metadata_candidates,
    }


def score_result(result: dict[str, Any]) -> int:
    score = 0
    hit_keywords = {h["keyword"] for h in result["hits"]}
    present = set(result["present_model_files"])

    if "model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer" in hit_keywords:
        score += 100
    if "v18-ml95-v2-normalizer" in hit_keywords:
        score += 70
    if "semantic-normalizer-v18-ml95-v2-safe-dynamic-sql" in hit_keywords:
        score += 40
    if '"threshold": 0.96' in hit_keywords or '"threshold":0.96' in hit_keywords or "threshold= 0.96" in hit_keywords:
        score += 30

    required = {
        "sqli_model.npz",
        "sqli_detection_metadata.json",
        "sqli_detection_vocab.json",
        "sqli_detection_label_maps.json",
    }
    score += 5 * len(present & required)
    if required.issubset(present):
        score += 30

    for meta in result["metadata_candidates"]:
        if meta.get("model_version") == "model1-cnn-bilstm-dual-head-v18-ml95-v2-normalizer":
            score += 200
        if str(meta.get("threshold")) == "0.96":
            score += 50
        if meta.get("normalizer_version") == "semantic-normalizer-v18-ml95-v2-safe-dynamic-sql":
            score += 30

    return score


def main() -> int:
    downloads = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads"
    search_root = Path(sys.argv[1]) if len(sys.argv) > 1 else downloads

    if not search_root.exists():
        print(f"Search folder does not exist: {search_root}")
        return 2

    zip_files = sorted(search_root.rglob("*.zip"))
    print(f"Searching {len(zip_files)} ZIP files under: {search_root}")
    print()

    all_results: list[dict[str, Any]] = []
    for zp in zip_files:
        result = search_zip(zp)
        result["score"] = score_result(result)
        if result["score"] or result["hits"] or result["metadata_candidates"]:
            all_results.append(result)

    all_results.sort(key=lambda r: r["score"], reverse=True)

    print("=== TOP CANDIDATES ===")
    if not all_results:
        print("No matching ZIPs found.")
    else:
        for idx, r in enumerate(all_results[:30], start=1):
            print(f"\n#{idx} score={r['score']}")
            print(f"ZIP: {r['zip']}")
            if r["error"]:
                print(f"ERROR: {r['error']}")

            if r["present_model_files"]:
                print("Model files:", ", ".join(r["present_model_files"]))

            for meta in r["metadata_candidates"][:5]:
                print("Metadata:")
                print(f"  file_inside_zip: {meta.get('file_inside_zip')}")
                print(f"  model_version:   {meta.get('model_version')}")
                print(f"  threshold:       {meta.get('threshold')}")
                print(f"  selected_thr:    {meta.get('selected_threshold')}")
                print(f"  normalizer:      {meta.get('normalizer_version')}")
                print(f"  training_date:   {meta.get('training_date_utc')}")
                print(f"  vocab_sha256:    {meta.get('vocabulary_sha256')}")

            if r["hits"]:
                print("Hits:")
                for h in r["hits"][:10]:
                    print(f"  - {h['keyword']}  inside: {h['file_inside_zip']}")

    out_csv = search_root / "v18_ml95_v2_zip_search_results.csv"
    with out_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "score",
                "zip",
                "file_inside_zip",
                "keyword",
                "model_files",
                "metadata_model_version",
                "metadata_threshold",
                "metadata_normalizer_version",
                "metadata_training_date_utc",
            ],
        )
        writer.writeheader()
        for r in all_results:
            meta = r["metadata_candidates"][0] if r["metadata_candidates"] else {}
            if r["hits"]:
                for h in r["hits"]:
                    writer.writerow({
                        "score": r["score"],
                        "zip": r["zip"],
                        "file_inside_zip": h["file_inside_zip"],
                        "keyword": h["keyword"],
                        "model_files": ";".join(r["present_model_files"]),
                        "metadata_model_version": meta.get("model_version", ""),
                        "metadata_threshold": meta.get("threshold", ""),
                        "metadata_normalizer_version": meta.get("normalizer_version", ""),
                        "metadata_training_date_utc": meta.get("training_date_utc", ""),
                    })
            else:
                writer.writerow({
                    "score": r["score"],
                    "zip": r["zip"],
                    "file_inside_zip": "",
                    "keyword": "",
                    "model_files": ";".join(r["present_model_files"]),
                    "metadata_model_version": meta.get("model_version", ""),
                    "metadata_threshold": meta.get("threshold", ""),
                    "metadata_normalizer_version": meta.get("normalizer_version", ""),
                    "metadata_training_date_utc": meta.get("training_date_utc", ""),
                })

    print()
    print(f"CSV written to: {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
