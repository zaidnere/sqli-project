"""
Code chunker — splits source files into function/method-level blocks.

This solves the long-file problem: a large file with many safe helper
functions and one hidden vulnerable function will have the vulnerable
function's signals buried far past the 128-token model window.

By analysing each function independently and taking the worst-case score
(max-pool), we ensure a single vulnerable function anywhere in the file
triggers the VULNERABLE verdict.

Supported languages: Python, JavaScript, PHP, Java
"""

import re
from typing import List, Tuple

# A chunk is (name, source_code)
Chunk = Tuple[str, str]


# ── Python ────────────────────────────────────────────────────────────────────

def _chunk_python(code: str) -> List[Chunk]:
    """
    Split Python code into (name, code) chunks at function/method boundaries.
    Falls back to the full file if no functions are found.
    """
    lines = code.split("\n")
    # Match lines that start a new def/class at any indentation level
    func_pattern = re.compile(r"^(\s*)(def |class )(\w+)")

    func_starts: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = func_pattern.match(line)
        if m:
            name = m.group(3)
            func_starts.append((i, name))

    if not func_starts:
        return [("__module__", code)]

    chunks: List[Chunk] = []
    for idx, (start_line, name) in enumerate(func_starts):
        end_line = func_starts[idx + 1][0] if idx + 1 < len(func_starts) else len(lines)
        block = "\n".join(lines[start_line:end_line])
        chunks.append((name, block))

    return chunks


# ── JavaScript ────────────────────────────────────────────────────────────────

def _chunk_javascript(code: str) -> List[Chunk]:
    """
    Split JavaScript/Node.js code into function-level chunks.
    Matches: function foo(), const foo = () =>, foo: function(), async foo()
    """
    lines = code.split("\n")
    func_pattern = re.compile(
        r"^\s*(?:async\s+)?(?:function\s+(\w+)|"
        r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)|"
        r"(\w+)\s*:\s*(?:async\s+)?function)"
    )

    func_starts: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = func_pattern.match(line)
        if m:
            name = m.group(1) or m.group(2) or m.group(3) or f"fn_{i}"
            func_starts.append((i, name))

    if not func_starts:
        return [("__module__", code)]

    chunks: List[Chunk] = []
    for idx, (start_line, name) in enumerate(func_starts):
        end_line = func_starts[idx + 1][0] if idx + 1 < len(func_starts) else len(lines)
        block = "\n".join(lines[start_line:end_line])
        chunks.append((name, block))

    return chunks


# ── PHP ───────────────────────────────────────────────────────────────────────

def _chunk_php(code: str) -> List[Chunk]:
    """Split PHP code at function/method boundaries."""
    lines = code.split("\n")
    func_pattern = re.compile(r"^\s*(?:public|private|protected|static)?\s*function\s+(\w+)")

    func_starts: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = func_pattern.match(line)
        if m:
            func_starts.append((i, m.group(1)))

    if not func_starts:
        return [("__module__", code)]

    chunks: List[Chunk] = []
    for idx, (start_line, name) in enumerate(func_starts):
        end_line = func_starts[idx + 1][0] if idx + 1 < len(func_starts) else len(lines)
        block = "\n".join(lines[start_line:end_line])
        chunks.append((name, block))

    return chunks


# ── Java ──────────────────────────────────────────────────────────────────────

def _chunk_java(code: str) -> List[Chunk]:
    """Split Java code at method boundaries."""
    lines = code.split("\n")
    # Match method signatures: public/private/protected ... returnType methodName(
    func_pattern = re.compile(
        r"^\s*(?:public|private|protected|static|final|synchronized|\s)+"
        r"[\w<>\[\]]+\s+(\w+)\s*\("
    )

    func_starts: List[Tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = func_pattern.match(line)
        if m and m.group(1) not in ("if", "for", "while", "switch", "catch"):
            func_starts.append((i, m.group(1)))

    if not func_starts:
        return [("__module__", code)]

    chunks: List[Chunk] = []
    for idx, (start_line, name) in enumerate(func_starts):
        end_line = func_starts[idx + 1][0] if idx + 1 < len(func_starts) else len(lines)
        block = "\n".join(lines[start_line:end_line])
        chunks.append((name, block))

    return chunks


# ── Public interface ──────────────────────────────────────────────────────────

_CHUNKERS = {
    "python":     _chunk_python,
    "javascript": _chunk_javascript,
    "php":        _chunk_php,
    "java":       _chunk_java,
}


def split_into_chunks(code: str, language: str) -> List[Chunk]:
    """
    Split source code into function/method-level chunks.

    Returns a list of (name, code) tuples. The first entry is always
    the full file under the key "__file__" so callers can also run
    file-level analysis. Each function then gets its own entry.

    If chunking yields only one block (no functions found), only the
    full-file entry is returned (no duplication).
    """
    chunker = _CHUNKERS.get(language, _chunk_python)
    function_chunks = chunker(code)

    # Always include the full file as the first chunk
    all_chunks: List[Chunk] = [("__file__", code)]

    # Only add function chunks if there are multiple (i.e. chunking found structure)
    if len(function_chunks) > 1:
        all_chunks.extend(function_chunks)

    return all_chunks
