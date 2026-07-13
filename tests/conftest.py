from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_findings_csv() -> Path:
    return FIXTURES_DIR / "sample_findings.csv"


@pytest.fixture
def sample_architecture_md() -> Path:
    return FIXTURES_DIR / "sample_architecture.md"
