"""
tests/test_llm_client.py — Tests for LLM client caching and no-live-calls mode.

Verifies caching, model digest pinning, and replay from cache.
"""

import json
import tempfile
from pathlib import Path

import pytest

from pre.llm.client import LLMClient, LLMResponse


def test_llm_cache_hit():
    """Test cache hit behavior."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cache"
        client = LLMClient(cache_dir=cache_dir, live_calls_enabled=True)

        # Manually create cache entry
        cache_key = client._cache_key("ollama:llama3.1:abc", "test prompt", None)
        cache_file = cache_dir / f"{cache_key}.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "text": "cached response",
            "model_digest": "ollama:llama3.1:abc",
            "tokens_used": 100,
        }
        cache_file.write_text(json.dumps(cached_data))

        # Call client - should hit cache
        response = client.call(
            prompt="test prompt",
            model_digest="ollama:llama3.1:abc",
        )

        assert response.text == "cached response"
        assert response.cached is True
        assert response.tokens_used == 100


def test_llm_no_live_calls_mode():
    """Test no-live-calls mode raises error on cache miss."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cache"
        client = LLMClient(cache_dir=cache_dir, live_calls_enabled=False)

        # Try to call with cache miss - should raise
        with pytest.raises(RuntimeError, match="Live calls disabled"):
            client.call(
                prompt="unknown prompt",
                model_digest="ollama:llama3.1:xyz",
            )


def test_llm_cache_key_deterministic():
    """Test that cache key is deterministic."""
    with tempfile.TemporaryDirectory() as tmpdir:
        client = LLMClient(cache_dir=tmpdir)

        key1 = client._cache_key("model1", "prompt1", "system1")
        key2 = client._cache_key("model1", "prompt1", "system1")
        key3 = client._cache_key("model2", "prompt1", "system1")

        assert key1 == key2
        assert key1 != key3


def test_llm_response_creation():
    """Test LLMResponse creation."""
    response = LLMResponse(
        text="test response",
        model_digest="ollama:llama3.1:abc",
        cached=False,
        tokens_used=50,
    )

    assert response.text == "test response"
    assert response.model_digest == "ollama:llama3.1:abc"
    assert response.cached is False
    assert response.tokens_used == 50


def test_llm_cache_persistence():
    """Test that cache persists across client instances."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "cache"

        # Create cache entry with first client
        client1 = LLMClient(cache_dir=cache_dir, live_calls_enabled=True)
        cache_key = client1._cache_key("model1", "prompt1", None)
        response1 = LLMResponse(
            text="response1",
            model_digest="model1",
            cached=False,
            tokens_used=100,
        )
        client1._save_cache(cache_key, response1)

        # Read with second client
        client2 = LLMClient(cache_dir=cache_dir, live_calls_enabled=False)
        response2 = client2.call("prompt1", "model1")

        assert response2.text == "response1"
        assert response2.cached is True


def test_llm_cache_dir_creation():
    """Test that cache directory is created automatically."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "deep" / "nested" / "cache"
        client = LLMClient(cache_dir=cache_dir)

        assert cache_dir.exists()
