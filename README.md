# SOCO Folder Clean

Clinic-safe organizer for SOCOM clinic folders. Hashes files, classifies them, dedupes/versions, moves to a clean structure, writes reports, and can run via CLI or a simple Tkinter GUI. Includes guardrails so Airmen can run it safely.

## What it does
- Classifies common clinic documents and separates Current vs Archive.
- Hashes files to detect duplicates; versions older copies.
- Clinic-safe mode: timestamps older files, never overwrites, makes a backup copy before moving.
- Dry-run mode for safe previews; verbose breakdown and CSV/JSON reports.
- GUI launcher for non-technical users; config file for plug-and-play runs.

## Quick start
### Fastest run (dry-run)
```bash
python main.py --input example-data --dest out --dry-run --clinic-safe
```

### With config (no flags needed)
1) Edit `config.toml` paths to match your clinic folders.  
2) Run:
```bash
python main.py
```

### GUI mode
```bash
python main.py --gui
```
Pick Source/Destination, leave “Dry run first” checked for the first pass, then hit **Go**.

### Mac
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .
python main.py --dry-run --clinic-safe
```

### Windows (PowerShell)
```powershell
python -m venv .venv
.\\.venv\\Scripts\\activate
pip install --upgrade pip
pip install .
python main.py --dry-run --clinic-safe
```

## Config file
`config.toml` is loaded automatically when no CLI flags are passed (or when `--config` is provided). Example:
```toml
[input]
source = "/Users/tech/Desktop/SOCOM-INBOX"

[output]
destination = "/Users/tech/Desktop/SOCOM-Clean"

[options]
dry_run = true
archive_old = true
verbose = true
clinic_safe = true
assume_yes = false
include_hidden = false
follow_symlinks = false
# backup_root = "/Users/tech/Desktop/SOCOM-Backups"
```
CLI flags override config values.

## Clinic-safe mode (`--clinic-safe`)
- Makes a backup of the source folder (default next to your input as `<input>-Backups`).
- Timestamps older/archived files to prevent name collisions.
- Refuses to overwrite existing files; reports any skipped moves.
- Skips deleting/renaming outside controlled moves.

## Reports
Written to `<dest>/Reports` (unless dry-run):
- `file_index.csv` — all files and targets.
- `duplicates.csv`, `deprecated.csv` — flagged items.
- `final_structure.json` — machine-readable summary.

## Example data
`example-data/` is bundled with four dummy files. Try:
```bash
python main.py --input example-data --dest example-out --dry-run --clinic-safe
```
Review `example-out/Reports` after a non-dry run to see the structure.

## Packaging for Airmen
### One-file binaries (recommended)
```bash
pip install pyinstaller
pyinstaller --onefile --name soco-clean main.py
```
- macOS output: `dist/soco-clean` (can live in `/usr/local/bin` or Desktop).
- Windows output: `dist/soco-clean.exe` (run from Downloads).

### Pipx install (optional)
```bash
pipx install .
soco-clean --dry-run --clinic-safe
```

### Release checklist
- Bump version in `pyproject.toml` (already at 1.0.0).
- Tag and push: `git tag -a v1.0.0 -m "Clinic-ready release"` then `git push origin v1.0.0`.
- Publish binaries (macOS + Windows) plus a ZIP of the repo and a `CHANGELOG.md`.

## Troubleshooting
- “Destination does not exist”: the CLI will ask to create it (or pass `--yes`).
- “Could not move (file may be open)”: close the document and rerun.
- Empty run: ensure `--input` points to a folder with files; hidden files are skipped unless `--include-hidden`.
- Backups growing large: point `backup_root` to another drive and clean old snapshots.

## Contact
Add your clinic POC or maintainer name/email/Teams handle here so Airmen know who owns the tool.
