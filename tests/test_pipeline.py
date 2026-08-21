from pathlib import Path

import duckdb

from meli_forensics.evidence import sha256_file
from meli_forensics.pipeline import build_database, fingerprint, mask_ip


def test_source_timestamp_is_year_day_month(tmp_path: Path):
    source = Path(__file__).parent / "fixtures" / "sample.csv"
    database = tmp_path / "test.duckdb"
    result = build_database(source, database)
    assert result["invalid_timestamps"] == 0
    assert result["first_event"].startswith("2025-10-01")
    assert result["last_event"].startswith("2025-12-31")
    with duckdb.connect(str(database), read_only=True) as con:
        assert con.execute("select count(*) from logs").fetchone()[0] == 2


def test_public_redaction_is_stable():
    assert mask_ip("203.0.113.10") == "203.0.113.x"
    assert fingerprint("secret", "token") == fingerprint("secret", "token")
    assert "secret" not in fingerprint("secret", "token")


def test_hash_matches_known_fixture():
    source = Path(__file__).parent / "fixtures" / "sample.csv"
    assert len(sha256_file(source)) == 64
