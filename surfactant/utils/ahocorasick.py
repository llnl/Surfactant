# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from typing import Any

from surfactant.utils.regex import extract_fixed_literals


# pylint: disable=too-few-public-methods
class AhoCorasickNode:
    """Node in the Aho-Corasick trie structure."""

    def __init__(self):
        self.goto = {}  # Goto function
        self.out = []  # Output function - list of pattern indices at this node
        self.fail = None  # Failure function
        self.depth = 0  # Depth of the node in the trie


class AhoCorasick:
    """Aho-Corasick automaton for fast multiple string matching."""

    def __init__(self, is_bytes: bool = False, encoding: str = "utf-8"):
        self.root = AhoCorasickNode()
        self.built = False
        self.is_bytes = is_bytes  # Flag to indicate if this automaton works with bytes
        self.pattern_prefixes = {}  # Maps pattern_id -> prefix used
        self.encoding = encoding  # Encoding to use for string/bytes conversion

    def add_pattern(self, pattern: str | bytes, pattern_id: Any, prefix: str) -> None:
        """
        Add a pattern to the trie.

        Args:
            pattern: A string or bytes pattern to add
            pattern_id: An identifier for this pattern
            prefix: The prefix string used for this pattern
        """
        # Ensure pattern is in the correct type (str or bytes)
        if self.is_bytes and isinstance(pattern, str):
            pattern = pattern.encode(self.encoding)
        elif not self.is_bytes and isinstance(pattern, bytes):
            pattern = pattern.decode(self.encoding, errors="ignore")

        node = self.root
        for i, char in enumerate(pattern):
            # For bytes, comparison char will be int values for the byte
            if char not in node.goto:
                node.goto[char] = AhoCorasickNode()
                node.goto[char].depth = i + 1
            node = node.goto[char]
        node.out.append(pattern_id)

        # Store the prefix used for this pattern_id
        self.pattern_prefixes[pattern_id] = prefix

    def build_automaton(self) -> None:
        """Build the Aho-Corasick automaton by computing failure functions."""
        queue = []
        # Set failure of all depth 1 nodes to root
        for _char, node in self.root.goto.items():
            node.fail = self.root
            queue.append(node)

        # Build failure function for the rest
        while queue:
            current = queue.pop(0)
            for char, node in current.goto.items():
                queue.append(node)
                failure = current.fail
                while failure and char not in failure.goto:
                    failure = failure.fail
                if not failure:
                    node.fail = self.root
                else:
                    node.fail = failure.goto[char]
                    # Add output patterns from failure node
                    node.out.extend(node.fail.out)

        self.built = True

    def search(self, text: str | bytes) -> dict[Any, list[int]]:
        """
        Search for patterns in the text and return matching pattern IDs with their positions.

        Args:
            text: A string or bytes to search in

        Returns:
            A dictionary mapping pattern IDs to lists of positions where prefixes were found
        """
        if not self.built:
            self.build_automaton()

        # Ensure text is in the correct type (str or bytes)
        if self.is_bytes and isinstance(text, str):
            text = text.encode(self.encoding)
        elif not self.is_bytes and isinstance(text, bytes):
            text = text.decode(self.encoding, errors="ignore")

        node = self.root
        results = {}

        for i, char in enumerate(text):
            # For bytes, char will be int value of the byte
            char = text[i]

            while node is not self.root and char not in node.goto:
                node = node.fail

            if char in node.goto:
                node = node.goto[char]
                if node.out:
                    for pattern_id in node.out:
                        if pattern_id not in results:
                            results[pattern_id] = []
                        # Store the start position by subtracting the node depth
                        prefix_length = len(self.pattern_prefixes.get(pattern_id, ""))
                        if self.is_bytes and isinstance(
                            prefix := self.pattern_prefixes.get(pattern_id, ""), str
                        ):
                            prefix_length = len(prefix.encode(self.encoding))

                        # Calculate the start position of the match
                        start_pos = max(0, i + 1 - prefix_length)
                        results[pattern_id].append(start_pos)

        return results


def build_regex_literal_matcher(
    patterns_dict: dict[Any, str],
    is_bytes: bool = False,
    encoding: str = "utf-8",
    is_literal: bool = False,
) -> AhoCorasick:
    """
    Build an Aho-Corasick automaton for matching regex literal strings, typically prefixes.

    Args:
        patterns_dict: Dictionary mapping pattern IDs to regex patterns
        is_bytes: Flag indicating if the automaton should work with bytes
        encoding: Character encoding to use for string/bytes conversion (default: utf-8)
        is_literal: Flag indicating if the patterns should be treated as regex literals (default: False)

    Returns:
        An Aho-Corasick automaton for prefix matching
    """
    ac = AhoCorasick(is_bytes=is_bytes, encoding=encoding)

    for pattern_id, pattern in patterns_dict.items():
        # For fixed literals, we can directly add them to the automaton
        if is_literal:
            ac.add_pattern(pattern, pattern_id, pattern)
            continue
        literals, is_prefix = extract_fixed_literals(pattern)
        if len(literals) > 10:  # Skip excessive number of prefixes
            continue
        if (
            len(literals) == 1 and len(literals[0]) == 1
        ):  # Skip prefix if it just matches a single character
            continue
        for prefix in literals:
            if not prefix:  # Skip empty prefixes
                continue

            ac.add_pattern(prefix, pattern_id, prefix)

    ac.build_automaton()
    return ac
