import tarfile
import zipfile
from pathlib import Path
from typing import Iterator


def prepare(source_path: Path, dest_root: Path) -> Path:
    """Return a package root directory.

    If source_path is already a directory, it's used directly (no extraction).
    If it's a tarball/zip, it's extracted into dest_root and the package root is returned.
    """
    if source_path.is_dir():
        return _resolve_package_root(source_path)

    dest_root.mkdir(parents=True, exist_ok=True)
    target = dest_root / source_path.stem

    if zipfile.is_zipfile(source_path):
        with zipfile.ZipFile(source_path) as zf:
            zf.extractall(target)
    elif tarfile.is_tarfile(source_path):
        with tarfile.open(source_path) as tf:
            tf.extractall(target)
    else:
        raise ValueError(f"Unsupported archive format: {source_path}")

    return _resolve_package_root(target)


def _resolve_package_root(extracted_dir: Path) -> Path:
    """npm tarballs typically wrap content under a single 'package/' dir."""
    if (extracted_dir / "package.json").exists():
        return extracted_dir
    try:
        entries = [p for p in extracted_dir.iterdir() if p.is_dir()]
    except OSError:
        return extracted_dir
    if len(entries) == 1 and (entries[0] / "package.json").exists():
        return entries[0]
    return extracted_dir


def iter_js_files(package_root: Path) -> Iterator[Path]:
    skip_dirs = {"node_modules", ".git", "test", "tests", "__tests__"}
    js_exts = {".js", ".cjs", ".mjs", ".ts"}

    stack = [package_root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name in skip_dirs:
                        continue
                    stack.append(entry)
                elif entry.is_file() and entry.suffix.lower() in js_exts:
                    yield entry
            except OSError:
                continue
