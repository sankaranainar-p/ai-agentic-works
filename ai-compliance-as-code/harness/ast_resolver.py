"""
harness/ast_resolver.py — Resolves line-level hits into enclosing class/method AST nodes using tree-sitter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Tree-sitter node type sets
_JAVA_CLASS_NODES = {
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
}
_JAVA_METHOD_NODES = {
    "method_declaration",
    "constructor_declaration",
}

_KOTLIN_CLASS_NODES = {
    "class_declaration",
    "object_declaration",
}
_KOTLIN_METHOD_NODES = {
    "function_declaration",
    "secondary_constructor",
}

_IDENTIFIER_TYPES = {"identifier", "type_identifier", "simple_identifier"}


@dataclass
class ASTNodeInfo:
    """Information about an enclosing AST node (class, interface, or method)."""

    node_type: str
    name: str
    start_line: int  # 1-indexed
    end_line: int  # 1-indexed
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    qualified_name: str = ""

    def contains_line(self, line: int) -> bool:
        """Check whether the given 1-indexed line is inside this node's span."""
        return self.start_line <= line <= self.end_line

    def contains_span(self, start: int, end: int) -> bool:
        """Check whether the given span is entirely inside this node's span."""
        return self.start_line <= start and end <= self.end_line

    def overlaps_span(self, start: int, end: int) -> bool:
        """Check whether the given span overlaps with this node's span."""
        return not (end < self.start_line or start > self.end_line)


class ASTResolver:
    """Resolves line numbers in Java and Kotlin code to enclosing AST nodes."""

    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {}
        self._languages: dict[str, Any] = {}

    def _init_parser(self, lang: str) -> None:
        if lang in self._parsers:
            return

        import tree_sitter

        if lang == "java":
            import tree_sitter_java

            language = tree_sitter.Language(tree_sitter_java.language())
        elif lang == "kotlin":
            import tree_sitter_kotlin

            language = tree_sitter.Language(tree_sitter_kotlin.language())
        else:
            raise ValueError(f"Unsupported AST language: {lang}. Must be 'java' or 'kotlin'.")

        self._languages[lang] = language
        try:
            parser = tree_sitter.Parser(language)
        except TypeError:
            parser = tree_sitter.Parser()
            parser.language = language

        self._parsers[lang] = parser

    def detect_language(self, file_path_or_ext: str) -> str:
        """Detect language ('java' or 'kotlin') from filename or extension."""
        lower = file_path_or_ext.lower()
        if lower.endswith((".kt", ".kts")) or "kotlin" in lower:
            return "kotlin"
        return "java"

    def _get_node_name(self, node: Any, code_bytes: bytes) -> str:
        """Extract the identifier name of a class or method node."""
        for child in node.children:
            if child.type in _IDENTIFIER_TYPES:
                return code_bytes[child.start_byte : child.end_byte].decode(
                    "utf-8", errors="replace"
                )
        return ""

    def resolve_span(
        self,
        code: Union[str, bytes],
        start_line: Optional[int],
        end_line: Optional[int] = None,
        language: str = "java",
        file_path: Optional[str] = None,
    ) -> Optional[ASTNodeInfo]:
        """Resolve a line span into its innermost enclosing class or method AST node.

        Args:
            code: Source code string or bytes.
            start_line: 1-indexed starting line number. If None, returns None.
            end_line: 1-indexed ending line number. If None, defaults to start_line.
            language: 'java' or 'kotlin' (or inferred from file_path if given).
            file_path: Optional file path to infer language from extension.

        Returns:
            ASTNodeInfo describing the enclosing AST node, or None if outside any class/method.
        """
        if start_line is None:
            return None
        if end_line is None:
            end_line = start_line
        if end_line < start_line:
            start_line, end_line = end_line, start_line

        if file_path:
            language = self.detect_language(file_path)

        try:
            self._init_parser(language)
        except Exception as exc:
            logger.warning("Could not initialize parser for %s: %s", language, exc)
            return None

        code_bytes = code.encode("utf-8") if isinstance(code, str) else code
        parser = self._parsers.get(language)
        if parser is None:
            return None

        try:
            tree = parser.parse(code_bytes)
        except Exception as exc:
            logger.warning("Failed to parse code with tree-sitter: %s", exc)
            return None

        class_nodes = _JAVA_CLASS_NODES if language == "java" else _KOTLIN_CLASS_NODES
        method_nodes = _JAVA_METHOD_NODES if language == "java" else _KOTLIN_METHOD_NODES

        # Collect enclosing class and method nodes from root to leaf
        enclosing_classes: List[Tuple[str, int, int, str]] = []
        enclosing_methods: List[Tuple[str, int, int, str]] = []

        def traverse(node: Any) -> None:
            node_start = node.start_point.row + 1
            node_end = node.end_point.row + 1

            # Check if this node encloses the entire target span
            if not (node_start <= start_line and end_line <= node_end):
                return

            if node.type in class_nodes:
                name = self._get_node_name(node, code_bytes)
                enclosing_classes.append((name, node_start, node_end, node.type))
            elif node.type in method_nodes:
                name = self._get_node_name(node, code_bytes)
                enclosing_methods.append((name, node_start, node_end, node.type))

            for child in node.children:
                traverse(child)

        traverse(tree.root_node)

        # Innermost method takes precedence if present
        if enclosing_methods:
            method_name, m_start, m_end, m_type = enclosing_methods[-1]
            class_name = enclosing_classes[-1][0] if enclosing_classes else None
            qualified = f"{class_name}.{method_name}" if class_name else method_name
            return ASTNodeInfo(
                node_type=m_type,
                name=method_name,
                start_line=m_start,
                end_line=m_end,
                class_name=class_name,
                method_name=method_name,
                qualified_name=qualified,
            )

        # Otherwise, innermost class if present
        if enclosing_classes:
            class_name, c_start, c_end, c_type = enclosing_classes[-1]
            return ASTNodeInfo(
                node_type=c_type,
                name=class_name,
                start_line=c_start,
                end_line=c_end,
                class_name=class_name,
                method_name=None,
                qualified_name=class_name,
            )

        return None

    def resolve_line(
        self,
        code: Union[str, bytes],
        line: int,
        language: str = "java",
        file_path: Optional[str] = None,
    ) -> Optional[ASTNodeInfo]:
        """Convenience method to resolve a single line number."""
        return self.resolve_span(
            code,
            start_line=line,
            end_line=line,
            language=language,
            file_path=file_path,
        )

    def resolve_enclosing_scope(
        self,
        code: Union[str, bytes],
        line: int,
        language: str = "java",
        file_path: Optional[str] = None,
    ) -> Optional[ASTNodeInfo]:
        """Resolve enclosing class and method scope for a line number."""
        return self.resolve_span(
            code,
            start_line=line,
            end_line=line,
            language=language,
            file_path=file_path,
        )
