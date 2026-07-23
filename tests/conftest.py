from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from synth import brute_force_scenario


@pytest.fixture
def scenario(tmp_path: Path) -> tuple[Path, Path]:
    """An auth.log + wtmp pair describing a complete SSH intrusion."""
    return brute_force_scenario(tmp_path)
