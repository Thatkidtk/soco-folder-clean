from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional


STATUS_ACTIVE = "active"
STATUS_DUPLICATE = "duplicate"
STATUS_DEPRECATED = "deprecated"
STATUS_CANDIDATE = "candidate"


@dataclass
class FileRecord:
    source_path: Path
    relative_path: Path
    extension: str
    size_bytes: int
    created: dt.datetime
    modified: dt.datetime
    sha256: str
    normalized_base: str
    category: str = "Unsorted"
    status: str = STATUS_CANDIDATE
    target_path: Optional[Path] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize SOCOM Clinic documents by hashing, deduping, versioning, categorizing, and archiving."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("."),
        help="Root directory containing the raw SOCOM Clinic files.",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=None,
        help="Destination root for normalized output. Defaults to <input>/SOCOM-Clean.",
    )
    parser.add_argument(
        "--archive-date",
        type=str,
        default=None,
        help="Date label for archive folder (YYYY-MM-DD). Defaults to today.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate actions without moving files or writing reports.",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks while traversing.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Include hidden files and directories (those starting with '.').",
    )
    return parser.parse_args()


def normalize_basename(name: str) -> str:
    work = name.lower()
    work = re.sub(r"\d{2}[._-]?\d{2}[._-]?\d{2,4}", " ", work)
    work = re.sub(r"(19|20)\d{2}", " ", work)
    work = re.sub(r"v\d+", " ", work)
    for token in ("final", "new", "updated", "update", "old", "rev", "copy"):
        work = work.replace(token, " ")
    work = re.sub(r"[^a-z0-9]+", " ", work)
    work = re.sub(r"\s+", " ", work).strip()
    return work


def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def enumerate_files(
    root: Path, exclude_dirs: Iterable[str], follow_symlinks: bool, include_hidden: bool
) -> List[FileRecord]:
    records: List[FileRecord] = []
    exclude = set(exclude_dirs)
    for current_dir, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if d not in exclude and (include_hidden or not d.startswith("."))]
        current_path = Path(current_dir)
        for filename in filenames:
            if not include_hidden and filename.startswith("."):
                continue
            path = current_path / filename
            if not path.is_file():
                continue
            stat = path.stat()
            relative_path = path.relative_to(root)
            record = FileRecord(
                source_path=path,
                relative_path=relative_path,
                extension=path.suffix.lower(),
                size_bytes=stat.st_size,
                created=dt.datetime.fromtimestamp(stat.st_ctime),
                modified=dt.datetime.fromtimestamp(stat.st_mtime),
                sha256=sha256_file(path),
                normalized_base=normalize_basename(path.stem),
            )
            records.append(record)
    return records


def classify(record: FileRecord) -> str:
    name = record.source_path.name.lower()
    ext = record.extension
    if "script" in name or "provider" in name:
        return "Provider-Scripts"
    if "shpi" in name:
        return "SHPIs"
    if "pha" in name or "readiness" in name:
        return "Readiness-PHA"
    if "sop" in name or "instruction" in name or "policy" in name or "procedure" in name:
        return "SOPs"
    if "form" in name or "template" in name or "questionnaire" in name or ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
        return "Medical-Forms"
    return "Unsorted"


def classify_all(records: List[FileRecord]) -> None:
    for record in records:
        record.category = classify(record)


def _canonical_sort_key(record: FileRecord) -> tuple:
    return (-record.size_bytes, -record.modified.timestamp(), len(record.source_path.name), record.source_path.name.lower())


def detect_duplicates(records: List[FileRecord]) -> None:
    groups: Dict[str, List[FileRecord]] = {}
    for record in records:
        groups.setdefault(record.sha256, []).append(record)
    for group in groups.values():
        if len(group) == 1:
            continue
        group.sort(key=_canonical_sort_key)
        canonical = group[0]
        canonical.status = STATUS_ACTIVE
        for duplicate in group[1:]:
            duplicate.status = STATUS_DUPLICATE


def detect_versions(records: List[FileRecord]) -> None:
    groups: Dict[str, List[FileRecord]] = {}
    for record in records:
        if record.status == STATUS_DUPLICATE:
            continue
        groups.setdefault(record.normalized_base, []).append(record)
    for group in groups.values():
        if not group:
            continue
        group.sort(key=_canonical_sort_key)
        newest = group[0]
        newest.status = STATUS_ACTIVE
        for older in group[1:]:
            older.status = STATUS_DEPRECATED


def assign_targets(records: List[FileRecord], dest_root: Path, archive_date: str, create_dirs: bool) -> None:
    for record in records:
        if record.status == STATUS_ACTIVE:
            base_dir = dest_root / "Current" / record.category
        else:
            base_dir = dest_root / "Archive" / archive_date / record.category
        if create_dirs:
            base_dir.mkdir(parents=True, exist_ok=True)
        target = base_dir / record.source_path.name
        if target.exists():
            target = base_dir / f"{record.source_path.stem}_{record.sha256[:8]}{record.source_path.suffix}"
        record.target_path = target


def move_records(records: List[FileRecord], dry_run: bool) -> List[str]:
    actions: List[str] = []
    for record in records:
        if record.target_path is None:
            continue
        if dry_run:
            actions.append(f"[DRY RUN] {record.status.upper():<11} {record.source_path} -> {record.target_path}")
            continue
        record.target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(record.source_path), str(record.target_path))
        actions.append(f"{record.status.upper():<11} {record.source_path} -> {record.target_path}")
    return actions


def format_datetime(value: dt.datetime) -> str:
    return value.isoformat()


def write_csv(path: Path, records: Iterable[FileRecord]) -> None:
    fieldnames = [
        "file_path",
        "target_path",
        "sha256",
        "size_bytes",
        "created",
        "modified",
        "category",
        "status",
    ]
    with path.open("w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "file_path": str(record.source_path),
                    "target_path": str(record.target_path) if record.target_path else "",
                    "sha256": record.sha256,
                    "size_bytes": record.size_bytes,
                    "created": format_datetime(record.created),
                    "modified": format_datetime(record.modified),
                    "category": record.category,
                    "status": record.status,
                }
            )


def write_reports(dest_root: Path, records: List[FileRecord]) -> None:
    reports_dir = dest_root / "Reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_csv(reports_dir / "file_index.csv", records)
    write_csv(reports_dir / "duplicates.csv", [r for r in records if r.status == STATUS_DUPLICATE])
    write_csv(reports_dir / "deprecated.csv", [r for r in records if r.status == STATUS_DEPRECATED])
    final_json = [
        {
            "source_path": str(r.source_path),
            "target_path": str(r.target_path) if r.target_path else "",
            "sha256": r.sha256,
            "size_bytes": r.size_bytes,
            "created": format_datetime(r.created),
            "modified": format_datetime(r.modified),
            "category": r.category,
            "status": r.status,
        }
        for r in records
    ]
    (reports_dir / "final_structure.json").write_text(json.dumps(final_json, indent=2))


def main() -> None:
    args = parse_args()
    input_root = args.input.resolve()
    if not input_root.exists():
        raise SystemExit(f"Input root does not exist: {input_root}")
    dest_root = (input_root / "SOCOM-Clean") if args.dest is None else Path(args.dest).resolve()
    archive_date = args.archive_date or dt.date.today().isoformat()

    exclude_dirs = {"Current", "Archive", "Reports", ".git", "__pycache__", dest_root.name}
    records = enumerate_files(
        input_root,
        exclude_dirs=exclude_dirs,
        follow_symlinks=args.follow_symlinks,
        include_hidden=args.include_hidden,
    )
    if not records:
        print(f"No files found under {input_root}. Nothing to do.")
        return

    classify_all(records)
    detect_duplicates(records)
    detect_versions(records)
    assign_targets(records, dest_root=dest_root, archive_date=archive_date, create_dirs=not args.dry_run)

    total = len(records)
    duplicates = len([r for r in records if r.status == STATUS_DUPLICATE])
    deprecated = len([r for r in records if r.status == STATUS_DEPRECATED])
    active = len([r for r in records if r.status == STATUS_ACTIVE])

    print(f"Discovered {total} files under {input_root}")
    print(f"Active: {active} | Duplicates: {duplicates} | Deprecated: {deprecated}")
    print(f"Destination root: {dest_root}")

    actions = move_records(records, dry_run=args.dry_run)
    for action in actions:
        print(action)

    if args.dry_run:
        print("Dry-run complete. No files were moved and no reports were written.")
        return

    write_reports(dest_root, records)
    print(f"Reports written to {dest_root / 'Reports'}")


if __name__ == "__main__":
    main()
