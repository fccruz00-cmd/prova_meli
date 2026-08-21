from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path, PurePosixPath


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def extract_largest_csv(archive: Path, destination: Path) -> Path:
    """Safely extract the largest CSV from a ZIP archive."""
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zipped:
        candidates = []
        for item in zipped.infolist():
            member = PurePosixPath(item.filename)
            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"Unsafe ZIP member: {item.filename}")
            if not item.is_dir() and member.suffix.lower() == ".csv" and "__MACOSX" not in member.parts:
                candidates.append(item)
        if not candidates:
            raise ValueError("No CSV evidence found in archive")
        selected = max(candidates, key=lambda item: item.file_size)
        output = destination / Path(selected.filename).name
        if output.resolve().parent != destination:
            raise ValueError("Resolved evidence path escaped destination")
        with zipped.open(selected) as source, output.open("wb") as target:
            shutil.copyfileobj(source, target, length=8 * 1024 * 1024)
    return output


def resolve_evidence(input_path: Path, work_dir: Path) -> Path:
    if input_path.suffix.lower() == ".zip":
        return extract_largest_csv(input_path, work_dir)
    if input_path.suffix.lower() != ".csv":
        raise ValueError("Evidence must be a CSV or ZIP containing a CSV")
    return input_path.resolve()
