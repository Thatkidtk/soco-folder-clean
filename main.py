from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import tomllib


STATUS_ACTIVE = "active"
STATUS_DUPLICATE = "duplicate"
STATUS_DEPRECATED = "deprecated"
STATUS_CANDIDATE = "candidate"

DEFAULT_CONFIG_PATH = Path("config.toml")


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


@dataclass
class AppOptions:
    input_root: Path
    dest_root: Path
    archive_date: str
    dry_run: bool
    follow_symlinks: bool
    include_hidden: bool
    verbose: bool
    clinic_safe: bool
    archive_old: bool
    assume_yes: bool
    config_path: Optional[Path] = None
    backup_root: Optional[Path] = None


@dataclass
class RunResult:
    actions: List[str]
    errors: List[str]
    reports_dir: Optional[Path]
    records: List[FileRecord]


def parse_args(raw_args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize SOCOM Clinic documents by hashing, deduping, versioning, categorizing, and archiving."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to a config TOML file. If no CLI flags are provided, config.toml will be used automatically when present.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
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
        "--clinic-safe",
        action="store_true",
        help="Enable extra guardrails: backups, timestamped older files, and no overwrites.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose actions and summaries.",
    )
    parser.add_argument(
        "--archive-old",
        dest="archive_old",
        action="store_true",
        default=None,
        help="Place deprecated/duplicate files in Archive (default).",
    )
    parser.add_argument(
        "--no-archive-old",
        dest="archive_old",
        action="store_false",
        default=None,
        help="Keep older files alongside current output instead of Archive.",
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
    parser.add_argument(
        "--assume-yes",
        "--yes",
        dest="assume_yes",
        action="store_true",
        help="Auto-create missing destination paths without prompting.",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="Optional backup destination. Defaults to <dest>/Backups when clinic-safe is enabled.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the simple Tkinter GUI instead of the CLI run.",
    )
    return parser.parse_args(raw_args)


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
    root: Path,
    exclude_dirs: Iterable[str],
    follow_symlinks: bool,
    include_hidden: bool,
    errors: List[str],
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
            try:
                stat = path.stat()
                file_hash = sha256_file(path)
            except OSError as exc:
                errors.append(f"Skipped unreadable file {path}: {exc}")
                continue
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"Skipped file {path} due to unexpected error: {exc}")
                continue
            relative_path = path.relative_to(root)
            record = FileRecord(
                source_path=path,
                relative_path=relative_path,
                extension=path.suffix.lower(),
                size_bytes=stat.st_size,
                created=dt.datetime.fromtimestamp(stat.st_ctime),
                modified=dt.datetime.fromtimestamp(stat.st_mtime),
                sha256=file_hash,
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


def _canonical_sort_key(record: FileRecord) -> Tuple[int, float, int, str]:
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


def _timestamp_suffix(record: FileRecord) -> str:
    return record.modified.strftime("%Y%m%d-%H%M%S")


def _timestamp_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def _unique_target_path(target: Path, sha: str, prefer_timestamp: bool) -> Path:
    candidate = target
    counter = 1
    while candidate.exists():
        suffix = f"_{_timestamp_slug()}_{counter}" if prefer_timestamp else f"_{sha[:8]}_{counter}"
        candidate = target.with_name(f"{target.stem}{suffix}{target.suffix}")
        counter += 1
    return candidate


def assign_targets(
    records: List[FileRecord],
    dest_root: Path,
    archive_date: str,
    create_dirs: bool,
    archive_old: bool,
    clinic_safe: bool,
) -> None:
    for record in records:
        if record.status == STATUS_ACTIVE:
            base_dir = dest_root / "Current" / record.category
        elif archive_old:
            base_dir = dest_root / "Archive" / archive_date / record.category
        else:
            base_dir = dest_root / "Current" / record.category / "Older"
        if create_dirs:
            base_dir.mkdir(parents=True, exist_ok=True)

        target_stem = record.source_path.stem
        if clinic_safe and record.status != STATUS_ACTIVE:
            target_stem = f"{target_stem}_{_timestamp_suffix(record)}"
        target = base_dir / f"{target_stem}{record.source_path.suffix}"

        if target.exists():
            target = _unique_target_path(target, record.sha256, prefer_timestamp=clinic_safe)
        record.target_path = target


def move_records(records: List[FileRecord], dry_run: bool, clinic_safe: bool, errors: List[str]) -> List[str]:
    actions: List[str] = []
    for record in records:
        if record.target_path is None:
            continue
        action_label = f"{record.status.upper():<11} {record.source_path} -> {record.target_path}"
        if dry_run:
            actions.append(f"[DRY RUN] {action_label}")
            continue
        try:
            record.target_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            errors.append(f"Failed to create folder {record.target_path.parent}: {exc}")
            continue
        if record.target_path.exists():
            msg = f"Skipped move because target exists (clinic-safe): {record.target_path}" if clinic_safe else f"Skipped move because target exists: {record.target_path}"
            errors.append(msg)
            continue
        try:
            shutil.move(str(record.source_path), str(record.target_path))
            actions.append(action_label)
        except PermissionError as exc:
            errors.append(f"Could not move (file may be open): {record.source_path} -> {record.target_path} ({exc})")
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"Could not move {record.source_path} -> {record.target_path}: {exc}")
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


def write_reports(dest_root: Path, records: List[FileRecord], errors: List[str]) -> Optional[Path]:
    reports_dir = dest_root / "Reports"
    try:
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
    except OSError as exc:
        errors.append(f"Failed to write reports: {exc}")
        return None
    return reports_dir


def _get_cfg(config: Dict, section: str, key: str, default=None):
    block = config.get(section, {}) if isinstance(config, dict) else {}
    return block.get(key, default) if isinstance(block, dict) else default


def load_config(path: Path, required: bool) -> Dict:
    if not path.exists():
        if required:
            raise SystemExit(f"Config file not found: {path}")
        return {}
    try:
        return tomllib.loads(path.read_text())
    except Exception as exc:
        raise SystemExit(f"Could not read config file {path}: {exc}") from exc


def resolve_options(args: argparse.Namespace, raw_argv: List[str]) -> Tuple[AppOptions, Optional[str]]:
    use_config = args.config is not None or len(raw_argv) == 0
    config_path = args.config or DEFAULT_CONFIG_PATH
    config_data: Dict = load_config(config_path, required=args.config is not None) if use_config else {}
    config_notice = f"Loaded settings from {config_path}" if config_data else None

    input_root = args.input or Path(_get_cfg(config_data, "input", "source", "."))
    dest_from_config = _get_cfg(config_data, "output", "destination", None)
    dest_root = args.dest or (Path(dest_from_config) if dest_from_config else (input_root / "SOCOM-Clean"))
    archive_date = args.archive_date or _get_cfg(config_data, "options", "archive_date", None) or dt.date.today().isoformat()
    dry_run = bool(args.dry_run or _get_cfg(config_data, "options", "dry_run", False))
    clinic_safe = bool(args.clinic_safe or _get_cfg(config_data, "options", "clinic_safe", False))
    verbose = bool(args.verbose or _get_cfg(config_data, "options", "verbose", False))
    follow_symlinks = bool(args.follow_symlinks or _get_cfg(config_data, "options", "follow_symlinks", False))
    include_hidden = bool(args.include_hidden or _get_cfg(config_data, "options", "include_hidden", False))
    archive_old_cfg = _get_cfg(config_data, "options", "archive_old", True)
    archive_old = args.archive_old if args.archive_old is not None else bool(archive_old_cfg)
    assume_yes = bool(args.assume_yes or _get_cfg(config_data, "options", "assume_yes", False))
    backup_root_cfg = _get_cfg(config_data, "options", "backup_root", None)
    backup_root = args.backup_dir or (Path(backup_root_cfg).expanduser() if backup_root_cfg else None)

    options = AppOptions(
        input_root=input_root.resolve(),
        dest_root=dest_root.resolve(),
        archive_date=archive_date,
        dry_run=dry_run,
        follow_symlinks=follow_symlinks,
        include_hidden=include_hidden,
        verbose=verbose,
        clinic_safe=clinic_safe,
        archive_old=archive_old,
        assume_yes=assume_yes,
        config_path=config_path if config_data else None,
        backup_root=backup_root.resolve() if isinstance(backup_root, Path) else None,
    )
    if options.clinic_safe and options.backup_root is None:
        options.backup_root = (options.input_root.parent / f"{options.input_root.name}-Backups").resolve()
    return options, config_notice


def ensure_destination(dest_root: Path, dry_run: bool, assume_yes: bool) -> None:
    if dest_root.exists():
        return
    if dry_run:
        print(f"[DRY RUN] Destination {dest_root} does not exist and would be created.")
        return
    if assume_yes:
        dest_root.mkdir(parents=True, exist_ok=True)
        return
    answer = input(f"Destination {dest_root} does not exist. Create it? [y/N]: ").strip().lower()
    if answer in {"y", "yes"}:
        dest_root.mkdir(parents=True, exist_ok=True)
    else:
        raise SystemExit("Aborted because destination does not exist.")


def create_backup_snapshot(input_root: Path, backup_root: Path, exclude_dirs: Iterable[str], errors: List[str]) -> Optional[Path]:
    try:
        backup_root.mkdir(parents=True, exist_ok=True)
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        target_dir = backup_root / f"{input_root.name}-backup-{timestamp}"
        ignore = shutil.ignore_patterns(*exclude_dirs)
        shutil.copytree(input_root, target_dir, dirs_exist_ok=False, ignore=ignore)
        return target_dir
    except Exception as exc:
        errors.append(f"Backup failed: {exc}")
        return None


def summarize_categories(records: List[FileRecord]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        counts[record.category] = counts.get(record.category, 0) + 1
    return counts


def run_cleanup(options: AppOptions) -> RunResult:
    errors: List[str] = []
    if not options.input_root.exists():
        raise SystemExit(f"Input root does not exist: {options.input_root}")

    ensure_destination(options.dest_root, options.dry_run, options.assume_yes)
    exclude_dirs = {"Current", "Archive", "Reports", "Backups", ".git", "__pycache__", options.dest_root.name}
    records = enumerate_files(
        options.input_root,
        exclude_dirs=exclude_dirs,
        follow_symlinks=options.follow_symlinks,
        include_hidden=options.include_hidden,
        errors=errors,
    )
    if not records:
        return RunResult(actions=[], errors=errors + [f"No files found under {options.input_root}. Nothing to do."], reports_dir=None, records=[])

    classify_all(records)
    detect_duplicates(records)
    detect_versions(records)
    assign_targets(
        records,
        dest_root=options.dest_root,
        archive_date=options.archive_date,
        create_dirs=not options.dry_run,
        archive_old=options.archive_old,
        clinic_safe=options.clinic_safe,
    )

    actions: List[str] = []
    if options.clinic_safe and not options.dry_run:
        backup_path = create_backup_snapshot(options.input_root, options.backup_root, exclude_dirs, errors)
        if backup_path:
            actions.append(f"Backup created at {backup_path}")

    actions.extend(move_records(records, dry_run=options.dry_run, clinic_safe=options.clinic_safe, errors=errors))

    reports_dir = None
    if not options.dry_run:
        reports_dir = write_reports(options.dest_root, records, errors)
        if reports_dir:
            actions.append(f"Reports written to {reports_dir}")

    return RunResult(actions=actions, errors=errors, reports_dir=reports_dir, records=records)


def print_summary(result: RunResult, options: AppOptions) -> None:
    if not result.records:
        for error in result.errors:
            print(error)
        return

    total = len(result.records)
    duplicates = len([r for r in result.records if r.status == STATUS_DUPLICATE])
    deprecated = len([r for r in result.records if r.status == STATUS_DEPRECATED])
    active = len([r for r in result.records if r.status == STATUS_ACTIVE])
    unsorted = len([r for r in result.records if r.category == "Unsorted"])

    print(f"Discovered {total} files under {options.input_root}")
    print(f"Active: {active} | Duplicates: {duplicates} | Deprecated: {deprecated} | Unsorted: {unsorted}")
    print(f"Destination root: {options.dest_root}")
    if options.clinic_safe:
        print("Clinic-safe mode: enabled (backups, timestamps on older files, no overwrites)")
    for action in result.actions:
        print(action)
    if result.errors:
        print("Issues encountered:")
        for err in result.errors:
            print(f" - {err}")
    if options.verbose:
        counts = summarize_categories(result.records)
        print("Category breakdown:")
        for category, count in sorted(counts.items()):
            print(f" - {category}: {count}")
    if options.dry_run:
        print("Dry-run complete. No files were moved and no reports were written.")


def launch_gui(options: AppOptions) -> None:
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    def choose_input():
        path = filedialog.askdirectory(title="Select source folder")
        if path:
            input_var.set(path)

    def choose_dest():
        path = filedialog.askdirectory(title="Select destination folder")
        if path:
            dest_var.set(path)

    def log_message(msg: str):
        log_box.configure(state="normal")
        log_box.insert(tk.END, msg + "\n")
        log_box.see(tk.END)
        log_box.configure(state="disabled")

    def run_cleanup_thread():
        run_button.configure(state="disabled")
        log_box.configure(state="normal")
        log_box.delete("1.0", tk.END)
        log_box.configure(state="disabled")

        def worker():
            thread_errors: List[str] = []
            try:
                ui_options = AppOptions(
                    input_root=Path(input_var.get()).resolve(),
                    dest_root=Path(dest_var.get()).resolve(),
                    archive_date=options.archive_date,
                    dry_run=dry_run_var.get(),
                    follow_symlinks=options.follow_symlinks,
                    include_hidden=include_hidden_var.get(),
                    verbose=True,
                    clinic_safe=clinic_safe_var.get(),
                    archive_old=options.archive_old,
                    assume_yes=True,
                    backup_root=options.backup_root,
                    config_path=options.config_path,
                )
                result = run_cleanup(ui_options)
                for action in result.actions:
                    root.after(0, lambda msg=action: log_message(msg))
                if result.errors:
                    for err in result.errors:
                        root.after(0, lambda msg=err: log_message(f"ERROR: {msg}"))
                root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Run complete",
                        f"Processed {len(result.records)} files.\nErrors: {len(result.errors)}",
                    ),
                )
            except SystemExit as exc:
                thread_errors.append(str(exc))
            except Exception as exc:  # pragma: no cover - GUI safety
                thread_errors.append(f"Unexpected failure: {exc}")
            finally:
                if thread_errors:
                    for msg in thread_errors:
                        root.after(0, lambda m=msg: log_message(f"ERROR: {m}"))
                    root.after(0, lambda: messagebox.showerror("Run failed", "\n".join(thread_errors)))
                root.after(0, lambda: run_button.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    root = tk.Tk()
    root.title("SOCO Folder Clean")

    input_var = tk.StringVar(value=str(options.input_root))
    dest_var = tk.StringVar(value=str(options.dest_root))
    dry_run_var = tk.BooleanVar(value=True)
    clinic_safe_var = tk.BooleanVar(value=options.clinic_safe)
    include_hidden_var = tk.BooleanVar(value=options.include_hidden)

    tk.Label(root, text="Source Folder").grid(row=0, column=0, sticky="w", padx=6, pady=4)
    tk.Entry(root, textvariable=input_var, width=60).grid(row=0, column=1, padx=6, pady=4)
    tk.Button(root, text="Browse", command=choose_input).grid(row=0, column=2, padx=6, pady=4)

    tk.Label(root, text="Destination Folder").grid(row=1, column=0, sticky="w", padx=6, pady=4)
    tk.Entry(root, textvariable=dest_var, width=60).grid(row=1, column=1, padx=6, pady=4)
    tk.Button(root, text="Browse", command=choose_dest).grid(row=1, column=2, padx=6, pady=4)

    tk.Checkbutton(root, text="Dry run first", variable=dry_run_var).grid(row=2, column=0, sticky="w", padx=6, pady=2)
    tk.Checkbutton(root, text="Clinic-safe guardrails", variable=clinic_safe_var).grid(row=2, column=1, sticky="w", padx=6, pady=2)
    tk.Checkbutton(root, text="Include hidden files", variable=include_hidden_var).grid(row=2, column=2, sticky="w", padx=6, pady=2)

    run_button = tk.Button(root, text="Go", command=run_cleanup_thread, width=12)
    run_button.grid(row=3, column=0, padx=6, pady=6, sticky="w")

    log_box = scrolledtext.ScrolledText(root, width=90, height=20, state="disabled")
    log_box.grid(row=4, column=0, columnspan=3, padx=6, pady=6, sticky="nsew")
    root.grid_columnconfigure(1, weight=1)
    root.grid_rowconfigure(4, weight=1)

    root.mainloop()


def main() -> None:
    raw_argv = sys.argv[1:]
    args = parse_args(raw_argv)
    options, config_notice = resolve_options(args, raw_argv)

    if args.gui:
        launch_gui(options)
        return

    if config_notice:
        print(config_notice)
    try:
        result = run_cleanup(options)
    except SystemExit as exc:
        print(exc)
        return
    except KeyboardInterrupt:
        print("Aborted by user.")
        return
    print_summary(result, options)


if __name__ == "__main__":
    main()
