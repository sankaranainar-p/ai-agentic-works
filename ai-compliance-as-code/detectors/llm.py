"""
detectors/llm.py — LLM-based detector implementing the Detector protocol.
"""

from __future__ import annotations

import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from api.schemas import ComplianceFinding
from prompts.user_turn import build_user_turn
from scanner.static_scanner import scan


class LLMDetector:
    """LLM-based compliance detector invoking the configured provider (Ollama or Anthropic)."""

    def __init__(
        self,
        call_llm_fn: Optional[Callable[[str, str], Tuple[str, str]]] = None,
    ) -> None:
        self._call_llm_fn = call_llm_fn

    def _resolve_call_llm(self) -> Callable[[str, str], Tuple[str, str]]:
        if self._call_llm_fn is not None:
            return self._call_llm_fn
        # Look up dynamically so unittest.mock.patch("api.main.call_llm") works seamlessly
        main_mod = sys.modules.get("api.main")
        if main_mod is not None and hasattr(main_mod, "call_llm"):
            return getattr(main_mod, "call_llm")
        from api.main import call_llm
        return call_llm

    def detect(
        self,
        code: str,
        *,
        file_path: str = "untitled",
        regulation: str = "GDPR",
        extra_context: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        """Analyze code using the LLM and return compliance findings."""
        findings, _ = self.detect_with_provider_info(
            code,
            file_path=file_path,
            regulation=regulation,
            extra_context=extra_context,
        )
        return findings

    def detect_with_provider_info(
        self,
        code: str,
        *,
        hint: Optional[Dict[str, Any]] = None,
        file_path: str = "untitled",
        regulation: str = "GDPR",
        extra_context: Optional[str] = None,
    ) -> Tuple[List[ComplianceFinding], str]:
        """Analyze code using the LLM, returning (findings, provider_name)."""
        import api.main

        hint_dict = hint if hint is not None else scan(code, file_path=file_path)
        rule_pack_path = api.main._resolve_rule_pack(regulation)
        system_prompt = api.main._system_prompt_for(regulation, rule_pack_path)

        user_turn = build_user_turn(
            code=code,
            file_path=file_path,
            context_hint=hint_dict,
            regulation_name=regulation,
            extra_context=extra_context,
        )

        call_fn = self._resolve_call_llm()
        raw_text, provider_label = call_fn(system_prompt, user_turn)
        findings = api.main._parse_findings(raw_text, file_path)
        return findings, provider_label
