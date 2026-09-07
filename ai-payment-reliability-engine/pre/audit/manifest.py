"""
pre/audit/manifest.py — Manifest recording all inputs to the pipeline run.

Records:
- Git commit hash and branch
- Dataset hashes
- Taxonomy hash
- Prompt hashes
- Model digests
- Random seeds
- Hardware info
- CLI arguments

Enables exact reproduction of any run given the manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Manifest:
    """Complete manifest of a pipeline run."""

    git_commit: str  # Git commit hash
    git_branch: str  # Git branch name
    dataset_hash: str  # Hash of dataset
    taxonomy_hash: str  # Hash of taxonomy.yaml
    prompt_hashes: dict[str, str]  # {prompt_name: sha256}
    model_digests: list[str]  # [model1, model2, ...]
    seeds: dict[str, int]  # {component: seed}
    hardware: dict  # CPU, GPU, memory info
    cli_args: list[str]  # sys.argv
    timestamp: float  # Unix seconds when run started


def compute_file_hash(path: str | Path) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def get_hardware_info() -> dict:
    """Get hardware information."""
    return {
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }


def get_git_info() -> tuple[str, str]:
    """Get current git commit and branch (placeholder)."""
    # In production, would call git rev-parse
    return "unknown_commit", "unknown_branch"


class ManifestWriter:
    """Write and read pipeline manifests."""

    def __init__(self, path: str | Path = "manifest.json"):
        """Initialize manifest writer.

        Args:
            path: Path to write manifest JSON
        """
        self.path = Path(path)

    def write(
        self,
        dataset_path: str | Path,
        taxonomy_path: str | Path,
        prompt_hashes: dict[str, str],
        model_digests: list[str],
        seeds: dict[str, int],
        timestamp: float,
    ) -> Manifest:
        """Write a manifest file.

        Args:
            dataset_path: Path to dataset file/directory
            taxonomy_path: Path to taxonomy.yaml
            prompt_hashes: Dict mapping prompt names to their SHA256 hashes
            model_digests: List of model identifiers (e.g., "ollama:llama3.1")
            seeds: Dict mapping component names to seeds
            timestamp: Unix seconds when run started

        Returns:
            Manifest object that was written
        """
        # Compute hashes
        dataset_hash = compute_file_hash(dataset_path)
        taxonomy_hash = compute_file_hash(taxonomy_path)

        # Get git info
        git_commit, git_branch = get_git_info()

        # Get hardware info
        hardware = get_hardware_info()

        manifest = Manifest(
            git_commit=git_commit,
            git_branch=git_branch,
            dataset_hash=dataset_hash,
            taxonomy_hash=taxonomy_hash,
            prompt_hashes=prompt_hashes,
            model_digests=model_digests,
            seeds=seeds,
            hardware=hardware,
            cli_args=sys.argv,
            timestamp=timestamp,
        )

        # Write to file
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(asdict(manifest), f, indent=2)

        return manifest

    def read(self) -> Optional[Manifest]:
        """Read manifest from file.

        Returns:
            Manifest object, or None if file doesn't exist
        """
        if not self.path.exists():
            return None

        with open(self.path) as f:
            data = json.load(f)
            return Manifest(**data)

    def validate(self) -> tuple[bool, str]:
        """Validate manifest file.

        Returns:
            (is_valid: bool, message: str)
        """
        if not self.path.exists():
            return False, "Manifest file does not exist"

        try:
            manifest = self.read()
            if not manifest:
                return False, "Failed to parse manifest"

            required_fields = [
                "git_commit", "dataset_hash", "taxonomy_hash",
                "prompt_hashes", "model_digests", "seeds"
            ]
            data = asdict(manifest)
            for field in required_fields:
                if field not in data:
                    return False, f"Missing required field: {field}"

            return True, "Manifest is valid"
        except Exception as e:
            return False, f"Validation error: {e}"
