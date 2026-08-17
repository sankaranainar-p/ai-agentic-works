"""
tests/test_llm_response_parsing.py — Unit tests for the LLM response
normalisation helpers in api.main.

These cover the messy real-world shapes a local model (Ollama) produces:
markdown fences, prose wrapped around the JSON, wrapper objects, and a bare
single finding object.  Each case must end up as a JSON array string that
json.loads() accepts, because /analyze silently falls back to static-only
findings whenever parsing fails.
"""

from __future__ import annotations

import json

import pytest

from api.main import _extract_json_array, _strip_fences


def _parsed(text: str):
    """Extract and parse, asserting the result is valid JSON."""
    extracted = _extract_json_array(text)
    try:
        return json.loads(extracted)
    except json.JSONDecodeError as exc:  # pragma: no cover - failure detail
        pytest.fail(f"extraction produced unparseable JSON: {exc}\nGot: {extracted!r}")


# ---------------------------------------------------------------------------
# _strip_fences
# ---------------------------------------------------------------------------

class TestStripFences:
    def test_plain_text_unchanged(self):
        assert _strip_fences('[{"rule_id": "A"}]') == '[{"rule_id": "A"}]'

    def test_json_fence_removed(self):
        assert _strip_fences('```json\n[{"a": 1}]\n```') == '[{"a": 1}]'

    def test_bare_fence_removed(self):
        assert _strip_fences('```\n[{"a": 1}]\n```') == '[{"a": 1}]'

    def test_unterminated_fence_removed(self):
        assert _strip_fences('```json\n[{"a": 1}]') == '[{"a": 1}]'

    def test_backticks_inside_payload_are_preserved(self):
        """Backticks inside a snippet are source code and must survive.

        The previous implementation stripped every backtick in the document,
        silently corrupting any finding whose snippet contained one.
        """
        payload = '[{"snippet": "SELECT * FROM `users`"}]'
        assert _strip_fences(payload) == payload
        assert _parsed(payload)[0]["snippet"] == "SELECT * FROM `users`"


# ---------------------------------------------------------------------------
# _extract_json_array
# ---------------------------------------------------------------------------

class TestExtractJsonArray:
    def test_plain_array(self):
        assert _parsed('[{"rule_id": "A"}]') == [{"rule_id": "A"}]

    def test_empty_array(self):
        assert _parsed("[]") == []

    def test_wrapper_object_is_unwrapped(self):
        assert _parsed('{"violations": [{"rule_id": "A"}]}') == [{"rule_id": "A"}]

    @pytest.mark.parametrize("key", ["violations", "findings", "results", "issues"])
    def test_all_wrapper_keys_unwrapped(self, key):
        assert _parsed(f'{{"{key}": [{{"rule_id": "A"}}]}}') == [{"rule_id": "A"}]

    def test_single_object_is_wrapped_in_array(self):
        result = _parsed('{"rule_id": "C", "severity": "high"}')
        assert result == [{"rule_id": "C", "severity": "high"}]

    def test_array_buried_in_prose(self):
        assert _parsed('Here are the findings: [{"rule_id": "A"}]') == [{"rule_id": "A"}]

    def test_trailing_prose_after_array(self):
        assert _parsed('[{"rule_id": "E"}] Hope this helps!') == [{"rule_id": "E"}]

    def test_prose_brackets_before_real_array(self):
        """Regression: a bracketed aside must not be mistaken for the array.

        A greedy regex matched from the first '[' of "[see rule 5]" through the
        final ']', yielding a slice that could never parse.
        """
        text = 'Note [see rule 5] — findings: [{"rule_id": "A"}]'
        assert _parsed(text) == [{"rule_id": "A"}]

    def test_object_appearing_before_array(self):
        """Regression: an object preceding the array must not break extraction.

        Previously this fell through every branch and returned a truncated
        slice, so a perfectly good findings array was discarded.
        """
        text = 'Summary {"count": 1} then [{"rule_id": "B"}]'
        assert _parsed(text) == [{"rule_id": "B"}]

    def test_fenced_wrapper_object_end_to_end(self):
        raw = '```json\n{"violations": [{"rule_id": "A", "severity": "high"}]}\n```'
        assert _parsed(_strip_fences(raw)) == [{"rule_id": "A", "severity": "high"}]

    def test_nested_arrays_inside_findings_survive(self):
        text = '[{"rule_id": "A", "references": ["http://x", "http://y"]}]'
        assert _parsed(text)[0]["references"] == ["http://x", "http://y"]

    def test_unparseable_text_returned_unchanged(self):
        """No JSON at all → return input so the caller raises a clear error."""
        assert _extract_json_array("I could not analyse this file.") == (
            "I could not analyse this file."
        )
