import argparse
import csv
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

from . import ast_analyzer, chain_features, extract_archive, package_json, regex_analyzer
from .csv_writer import CsvWriter
from .features import to_row


THREAT_TYPE_TO_LABEL = {
    "malware": 1,
    "false_positive": 0,
}
SKIP_THREAT_TYPES = {"unreviewed"}


def _log(msg: str, *, err: bool = False) -> None:
    stream = sys.stderr if err else sys.stdout
    print(msg, file=stream, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="npm malicious package feature extractor (MalwareBench)")
    parser.add_argument("metadata_csv", type=Path, help="MalwareBench metadata CSV (npm_package_info.csv)")
    parser.add_argument("output_csv", type=Path, help="output feature CSV")
    parser.add_argument(
        "--archive-dir",
        type=Path,
        default=None,
        help="directory containing npm archives. If omitted, metadata-only dry run.",
    )
    parser.add_argument(
        "--layout",
        choices=("dir", "tgz", "auto"),
        default="auto",
        help="archive layout: 'dir' = archive_dir/{name}/{version}/; 'tgz' = archive_dir/{group_id}.tgz; 'auto' = try dir then tgz",
    )
    parser.add_argument(
        "--source",
        default="malwarebench",
        help="dataset source tag written to CSV",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="process only first N usable rows (0 = all)",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="print progress line every N processed rows (default: 100)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log every package (including [ok]). default: only progress + missing/errors.",
    )
    parser.add_argument(
        "--max-detail-log",
        type=int,
        default=20,
        help="max number of per-package detail lines to print for missing/errors (rest suppressed). default: 20",
    )
    args = parser.parse_args()

    if not args.metadata_csv.exists():
        _log(f"[fatal] metadata CSV not found: {args.metadata_csv}", err=True)
        return 1

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="npm_feat_"))

    counts = {
        "processed": 0,
        "written": 0,
        "skipped_unreviewed": 0,
        "skipped_unknown_type": 0,
        "missing_archive": 0,
        "errors": 0,
    }
    detail_logged = {"missing": 0, "error": 0}

    start_ts = time.time()
    _log(f"[start] metadata={args.metadata_csv}")
    _log(f"[start] output={args.output_csv}")
    _log(f"[start] archive_dir={args.archive_dir}  layout={args.layout}")
    _log(f"[start] limit={args.limit or 'all'}  progress_every={args.progress_every}  verbose={args.verbose}")

    try:
        with args.metadata_csv.open("r", encoding="utf-8", newline="") as fh, \
             CsvWriter(args.output_csv) as writer:
            reader = csv.DictReader(fh)
            for row in reader:
                threat_type = (row.get("threat_type") or "").strip().lower()

                if threat_type in SKIP_THREAT_TYPES:
                    counts["skipped_unreviewed"] += 1
                    continue
                if threat_type not in THREAT_TYPE_TO_LABEL:
                    counts["skipped_unknown_type"] += 1
                    if args.verbose:
                        _log(f"[skip-unknown-type] threat_type={threat_type!r}", err=True)
                    continue

                label = THREAT_TYPE_TO_LABEL[threat_type]
                group_id = (row.get("group_ID") or "").strip()
                scoped = (row.get("scoped") or "").strip()
                name = (row.get("name") or "").strip()
                version = (row.get("version") or "").strip()

                counts["processed"] += 1

                if args.archive_dir is None:
                    feature_row = _empty_row(name, version, label, args.source, threat_type)
                    writer.write_row(feature_row)
                    counts["written"] += 1
                else:
                    archive = _locate_package(args.archive_dir, args.layout, scoped, group_id, name, version)
                    if archive is None:
                        counts["missing_archive"] += 1
                        if detail_logged["missing"] < args.max_detail_log:
                            _log(f"[missing] {name}@{version} (group_id={group_id})", err=True)
                            detail_logged["missing"] += 1
                        elif detail_logged["missing"] == args.max_detail_log:
                            _log(f"[missing] ... further missing logs suppressed (use --max-detail-log to raise)", err=True)
                            detail_logged["missing"] += 1
                    else:
                        try:
                            feature_row = _process_archive(
                                archive, workspace, name, version, label, args.source, threat_type
                            )
                            writer.write_row(feature_row)
                            counts["written"] += 1
                            if args.verbose:
                                _log(f"[ok] {name}@{version} label={label}")
                        except Exception as exc:
                            counts["errors"] += 1
                            if detail_logged["error"] < args.max_detail_log:
                                _log(f"[error] {name}@{version}: {type(exc).__name__}: {exc}", err=True)
                                traceback.print_exc(file=sys.stderr)
                                sys.stderr.flush()
                                detail_logged["error"] += 1
                            elif detail_logged["error"] == args.max_detail_log:
                                _log("[error] ... further tracebacks suppressed (use --max-detail-log to raise)", err=True)
                                detail_logged["error"] += 1

                if counts["processed"] % args.progress_every == 0:
                    _print_progress(counts, start_ts)

                if args.limit and counts["written"] >= args.limit:
                    _log(f"[limit] reached --limit {args.limit}, stopping")
                    break
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    elapsed = time.time() - start_ts
    _log("")
    _log(f"[done] elapsed={elapsed:.1f}s")
    _log(f"[done] output={args.output_csv}")
    for k, v in counts.items():
        _log(f"  {k}: {v}")
    return 0


def _print_progress(counts: dict, start_ts: float) -> None:
    elapsed = max(time.time() - start_ts, 1e-6)
    rate = counts["processed"] / elapsed
    _log(
        f"[progress] processed={counts['processed']} "
        f"written={counts['written']} "
        f"missing={counts['missing_archive']} "
        f"errors={counts['errors']} "
        f"rate={rate:.1f}/s "
        f"elapsed={elapsed:.0f}s"
    )


def _locate_package(archive_dir: Path, layout: str, scoped: str, group_id: str, name: str, version: str) -> Path | None:
    if layout in ("dir", "auto") and name and version:
        # scoped 패키지: archive_dir/@scope/name/version
        if scoped:
            candidate = archive_dir / scoped / name / version
            if candidate.is_dir():
                return candidate
        # flat: archive_dir/name/version
        candidate = archive_dir / name / version
        if candidate.is_dir():
            return candidate
    if layout in ("tgz", "auto") and group_id:
        candidate = archive_dir / f"{group_id}.tgz"
        if candidate.is_file():
            return candidate
    return None


def _process_archive(
    source_path: Path,
    workspace: Path,
    name: str,
    version: str,
    label: int,
    source: str,
    malicious_type: str,
) -> dict:
    is_dir = source_path.is_dir()
    extract_dest = workspace / f"{name}_{version}"
    pkg_root = extract_archive.prepare(source_path, extract_dest)

    meta, pkg_feats = package_json.parse(pkg_root)
    # CSV identifiers win over package.json (malicious packages may tamper with manifest)
    meta.package_name = name or meta.package_name
    meta.version = version or meta.version
    meta.label = label
    meta.source = source
    meta.malicious_type = malicious_type

    js_files = list(extract_archive.iter_js_files(pkg_root))
    ast_feats = ast_analyzer.analyze_files(js_files)
    # regex는 JS 외에 package.json 본문도 스캔.
    # envoy-curses 처럼 preinstall에 curl URL이 박힌 케이스를 잡기 위함.
    pkg_json_path = pkg_root / "package.json"
    regex_targets = js_files + ([pkg_json_path] if pkg_json_path.exists() else [])
    rgx_feats = regex_analyzer.analyze_files(regex_targets)
    chain_feats = chain_features.derive(pkg_feats, ast_feats, rgx_feats)

    row = to_row(meta, pkg_feats, ast_feats, rgx_feats, chain_feats)
    if not is_dir:
        shutil.rmtree(extract_dest, ignore_errors=True)
    return row


def _empty_row(name: str, version: str, label: int, source: str, malicious_type: str) -> dict:
    from .features import (
        AstFeatures,
        ChainFeatures,
        PackageJsonFeatures,
        PackageMeta,
        RegexFeatures,
    )
    meta = PackageMeta(
        package_name=name,
        version=version,
        label=label,
        source=source,
        malicious_type=malicious_type,
    )
    return to_row(meta, PackageJsonFeatures(), AstFeatures(), RegexFeatures(), ChainFeatures())


if __name__ == "__main__":
    sys.exit(main())
