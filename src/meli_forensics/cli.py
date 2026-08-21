from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence import resolve_evidence, sha256_file
from .pipeline import build_charts, build_database, export_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the invoice-log forensic pipeline")
    parser.add_argument("--input", required=True, type=Path, help="CSV or ZIP evidence")
    parser.add_argument("--work-dir", type=Path, default=Path("work"))
    parser.add_argument("--public-output", type=Path, default=Path("results/public"))
    parser.add_argument("--restricted-output", type=Path, default=Path("results/restricted"))
    parser.add_argument("--skip-geo", action="store_true")
    args = parser.parse_args()

    evidence = resolve_evidence(args.input, args.work_dir / "evidence")
    database = args.work_dir / "forensics.duckdb"
    integrity = {"evidence_path": str(evidence), "sha256": sha256_file(evidence)}
    integrity.update(build_database(evidence, database))
    summary = export_results(
        database,
        args.public_output,
        args.restricted_output,
        None if args.skip_geo else args.work_dir / ".ipwho_cache.json",
        geolocate=not args.skip_geo,
    )
    build_charts(args.public_output, args.public_output / "charts")
    print(json.dumps({"integrity": integrity, "summary": summary}, indent=2, default=str))


if __name__ == "__main__":
    main()
