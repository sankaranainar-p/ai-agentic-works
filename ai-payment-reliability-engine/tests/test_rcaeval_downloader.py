"""
tests/test_rcaeval_downloader.py — Tests for
data/scripts/download_rcaeval.py's checksum verification logic, without
requiring network access.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPT_PATH = (
    Path(__file__).parent.parent / "data" / "scripts" / "download_rcaeval.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("download_rcaeval", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


downloader = _load_module()


def _make_zip(tmp_path: Path, content: bytes) -> Path:
    zip_path = tmp_path / "fake.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("fake.txt", content)
    return zip_path


def test_checksums_table_has_all_re1_re2_datasets():
    expected = {"RE1-OB", "RE1-SS", "RE1-TT", "RE2-OB", "RE2-SS", "RE2-TT"}
    assert set(downloader.CHECKSUMS.keys()) == expected


def test_md5_matches_hashlib_reference(tmp_path):
    content = b"hello rcaeval"
    p = tmp_path / "sample.bin"
    p.write_bytes(content)
    assert downloader._md5(p) == hashlib.md5(content).hexdigest()


def test_unknown_dataset_raises():
    with pytest.raises(ValueError, match="Unknown RCAEval dataset"):
        downloader.download("NOT-A-REAL-DATASET", Path("/tmp/whatever"))


def test_download_rejects_size_mismatch(tmp_path):
    """A response shorter than the expected size must not be extracted."""
    fake_bytes = b"x" * 100  # far short of any real dataset's declared size

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            nonlocal fake_bytes
            chunk, fake_bytes = fake_bytes[:n], fake_bytes[n:]
            return chunk

    with patch.object(downloader, "urlopen", return_value=_FakeResponse()):
        with pytest.raises(ValueError, match="expected"):
            downloader.download("RE1-OB", tmp_path)

    # must not leave a partial zip lying around, and must not extract
    assert not (tmp_path / "RE1-OB.zip").exists()
    assert not (tmp_path / "RE1-OB").exists()


def test_download_rejects_checksum_mismatch(tmp_path):
    """Correct size but wrong content (bad checksum) must not be extracted."""
    expected_md5, expected_size = downloader.CHECKSUMS["RE1-OB"]
    # content whose length matches but whose bytes don't hash to expected_md5
    bad_content = b"\x00" * expected_size
    assert hashlib.md5(bad_content).hexdigest() != expected_md5

    class _FakeResponse:
        def __init__(self):
            self._remaining = bad_content

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            chunk, self._remaining = self._remaining[:n], self._remaining[n:]
            return chunk

    with patch.object(downloader, "urlopen", return_value=_FakeResponse()):
        with pytest.raises(ValueError, match="MD5 mismatch"):
            downloader.download("RE1-OB", tmp_path)

    assert not (tmp_path / "RE1-OB.zip").exists()
    assert not (tmp_path / "RE1-OB").exists()


def test_download_skips_already_extracted(tmp_path):
    (tmp_path / "RE1-OB").mkdir()
    with patch.object(downloader, "urlopen") as mock_urlopen:
        result = downloader.download("RE1-OB", tmp_path)
        mock_urlopen.assert_not_called()
    assert result == tmp_path / "RE1-OB"
