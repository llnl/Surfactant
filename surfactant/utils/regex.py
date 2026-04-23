# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import re
import sys

from loguru import logger

# Choose the appropriate module based on Python version
# Note that this is "undocumented" so could break -- may want to find/write an alternative library
if sys.version_info < (3, 11):
    # pylint: disable=deprecated-module
    import sre_parse as re_parser
else:
    import re._parser as re_parser


# pylint: disable=too-many-return-statements
def handle_escaped_literal(regex_pattern: str, i: int, length: int) -> tuple[str, int]:
    """
    Handles escaped literals in a regex pattern and returns the character to be added to the prefix
    and the number of positions to advance the index by.

    Parameters:
    regex_pattern (str): The regex pattern being parsed.
    i (int): The current index in the regex pattern.
    length (int): The total length of the regex pattern.

    Returns:
    Tuple[str, int]: A tuple containing the character to be added to the prefix and the number of positions
           to advance the index by. Returns (None, 0) if parsing should stop.
    """
    next_char = regex_pattern[i + 1]
    # Try to catch all potential escape sequences with non-literal meaning
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet
    # https://en.wikipedia.org/wiki/Regular_expression
    if next_char in "dDsSwWbBpPUukAaeZ0123456789":
        return None, 0
    if next_char in "rntvf0":
        escape_sequences = {"r": "\r", "n": "\n", "t": "\t", "v": "\v", "f": "\f", "0": "\0"}
        return escape_sequences[next_char], 2
    if next_char == "c":
        if (
            i + 2 < length
            and regex_pattern[i + 1] == "c"
            and regex_pattern[i + 2].isalpha()
            and regex_pattern[i + 2].isupper()
        ):
            control_char = chr(ord(regex_pattern[i + 2]) - ord("A") + 1)
            return control_char, 3
        return None, 0
    if next_char == "x":
        if i + 3 < length and all(
            c in "0123456789abcdefABCDEF" for c in regex_pattern[i + 2 : i + 4]
        ):
            return chr(int(regex_pattern[i + 2 : i + 4], 16)), 4
        return None, 0
    # Should be able to handle '\uhhhh' case, however there is an additional \u{hhhh} and \u{hhhhh} syntax
    # that may be used if a flag is enabled, which complicates things a bit
    return next_char, 2


def extract_fixed_prefixes(regex_pattern: str) -> list[str]:
    """
    Extracts the fixed string prefixes from a regex pattern, including handling
    escaped characters, expanding character classes, and handling capture groups
    with multiple prefixes separated by '|'.

    Parameters:
    regex_pattern (str): The regex pattern from which to extract the prefixes.

    Returns:
    list: A list of fixed string prefixes, or an empty list if no fixed prefix exists.
    """
    # Compile the regex pattern to ensure it's valid
    try:
        re.compile(regex_pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}") from None

    prefixes = []
    i = 0
    length = len(regex_pattern)

    # Ignore starting '^'
    if i < length and regex_pattern[i] == "^":
        i += 1

    # Handle character class at the start
    if i < length and regex_pattern[i] == "[":
        i += 1
        char_class = []
        if i < length and regex_pattern[i] == "^":
            # If the character class is negated, we can't handle it -- return an empty prefix list
            return []
        while i < length and regex_pattern[i] != "]":
            if regex_pattern[i] == "\\" and i + 1 < length:
                if regex_pattern[i + 1] == "b":
                    char_class.append("\b")
                    i += 2
                else:
                    next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
                    # If it's a special character class, we can't handle it -- return empty prefix list
                    if next_char is None:
                        return []
                    char_class.append(next_char)
                    i += i_delta
            elif (
                regex_pattern[i] == "-"
                and char_class
                and i + 1 < length
                and regex_pattern[i + 1] != "]"
            ):
                # A hyphen means we need to handle a range of prefixes from the previous character to the next one
                start_char = char_class.pop()
                end_char = regex_pattern[i + 1]
                char_class.extend(chr(c) for c in range(ord(start_char), ord(end_char) + 1))
                i += 2
            else:
                char_class.append(regex_pattern[i])
                i += 1
        i += 1  # Skip the closing ']'
        # Generate prefixes for each character in the class
        for char in char_class:
            prefixes.append(char)
    # Handle capture group at the start
    elif i < length and regex_pattern[i] == "(":
        i += 1
        if i < length and regex_pattern[i] == "?":
            return []  # Return early if it starts with a '?'
        group_content = []
        while i < length and regex_pattern[i] != ")":
            if regex_pattern[i] == "\\" and i + 1 < length:
                next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
                if next_char is None:
                    return []  # special character class, we can't handle this form of regex
                group_content.append(next_char)
                i += i_delta
            elif regex_pattern[i] == "(":
                return []  # Return early if it contains a nested capture group
            else:
                group_content.append(regex_pattern[i])
                i += 1
        i += 1  # Skip the closing ')'
        # Split the group content by '|'
        for part in "".join(group_content).split("|"):
            # Only consider alphanumeric prefixes
            if part.isalnum():
                prefixes.append(part)

    # Handle regular fixed prefix extraction
    prefix = []
    while i < length:
        char = regex_pattern[i]
        if char == "\\" and i + 1 < length:
            next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
            if next_char is None:
                break
            prefix.append(next_char)
            i += i_delta
        elif char.isalnum() or char in "_-,: '":
            prefix.append(char)
            i += 1
        else:
            break
    if prefix:
        prefixes = [p + "".join(prefix) for p in prefixes] if prefixes else ["".join(prefix)]

    return prefixes


# pylint: disable=too-few-public-methods
class RegexNode:
    """A node in the regex parse tree."""

    def __init__(self, op, value=None, children=None):
        self.op = op  # Operation type (LITERAL, BRANCH, etc.)
        self.value = value  # Value for this node (e.g., character for LITERAL)
        self.children = children if children is not None else []

    def __repr__(self):
        if self.value is not None:
            return f"RegexNode({self.op}, {repr(self.value)})"
        return f"RegexNode({self.op}, children={len(self.children)})"


def extract_fixed_literals(pattern, max_possibilities=10, min_length=3):
    """
    Extract fixed literals from a regular expression pattern.

    Args:
        pattern: The regular expression pattern to analyze.
        max_possibilities: Maximum number of different possibilities to generate.
        min_length: Minimum length threshold for a potential fixed string.

    Returns:
        A tuple containing:
        - A list of fixed literals that could be matched by the pattern
        - A boolean indicating whether the patterns are prefixes (True) or not (False)
    """
    try:
        # Parse the regex pattern
        parsed = re_parser.parse(pattern)

        # Convert to our tree structure
        regex_tree = build_regex_tree(parsed, re_parser)

        # First try to extract literal prefixes from the tree
        literals, is_prefix, _is_comprehensive = extract_prefix_from_tree(
            regex_tree, max_possibilities, min_length, re_parser
        )

        if literals:
            return literals, is_prefix

        # Try to find fixed internal literals from the tree
        literals = extract_internal_literals(regex_tree, max_possibilities, min_length, re_parser)
        return literals, False

    except (re.error, AttributeError, TypeError) as e:
        logger.error(f"Error processing regex pattern: {e}")
        return [], False


def build_regex_tree(parsed, parser):
    """Convert the parsed regex into a tree structure."""
    root = RegexNode("ROOT", children=[])

    for op, av in parsed:
        if op == parser.LITERAL:
            # Simple literal character
            root.children.append(RegexNode(op, value=chr(av)))

        elif op == parser.IN:
            # Character class [...]
            chars = extract_chars_from_class(av, parser)
            node = RegexNode(op, value=chars)
            root.children.append(node)

        elif op == parser.SUBPATTERN:
            # Subpattern (...)
            # Structure varies by Python version
            subpattern = av[3] if len(av) > 3 else av[1]
            subtree = build_regex_tree(subpattern, parser)
            node = RegexNode(op, children=subtree.children)
            root.children.append(node)

        elif op == parser.BRANCH:
            # Alternation a|b|c
            branches = av[1]
            branch_nodes = []

            for branch in branches:
                branch_tree = build_regex_tree(branch, parser)
                branch_nodes.append(branch_tree)

            node = RegexNode(op, children=branch_nodes)
            root.children.append(node)

        elif op == parser.MAX_REPEAT:
            # Repetition a*, a+, a{n,m}
            min_count, max_count, subpattern = av
            subtree = build_regex_tree(subpattern, parser)

            node = RegexNode(op, value=(min_count, max_count), children=[subtree])
            root.children.append(node)

        elif op == parser.AT:
            # Anchors (^, $)
            # We can ignore these for fixed prefix extraction
            continue

        else:
            # Any other operation (ANY, etc.)
            node = RegexNode(op, value=av)
            root.children.append(node)

    return root


def extract_chars_from_class(char_class, parser):
    """Extract characters from a character class."""
    chars = set()

    for op, av in char_class:
        if op == parser.LITERAL:
            # Single characters
            chars.add(chr(av))
        elif op == parser.RANGE:
            # Character ranges (e.g., a-z, 0-9)
            start, end = av
            for i in range(start, end + 1):
                chars.add(chr(i))

    return list(chars)


def extract_prefix_from_tree(node, max_possibilities, min_length, parser):
    """Extract literal prefixes from the regex tree."""
    if node.op == "ROOT":
        # Process child nodes sequentially for prefixes
        prefixes = []
        total_possibilities = 1
        is_prefix = True
        is_comprehensive = True

        for child in node.children:
            # Check if we can still continue with a fixed prefix
            child_prefixes, child_is_prefix, is_comprehensive = node_to_prefixes(
                child, max_possibilities // total_possibilities, parser
            )

            if not child_is_prefix:
                break

            if not child_prefixes:
                is_prefix = False
                break

            # If this would create too many possibilities, stop
            if len(child_prefixes) * total_possibilities > max_possibilities:
                is_prefix = False
                break

            # Combine current prefixes with child prefixes
            if not prefixes:
                prefixes = child_prefixes
            else:
                new_prefixes = []
                for prefix in prefixes:
                    for child_prefix in child_prefixes:
                        new_prefixes.append(prefix + child_prefix)
                prefixes = new_prefixes
            total_possibilities *= len(child_prefixes)

            # If the set of child prefixes returned was not comprehensive, we can't keep going
            if not is_comprehensive:
                is_comprehensive = False
                break

        # Filter by minimum length
        prefixes = [p for p in prefixes if len(p) >= min_length]
        return prefixes[:max_possibilities], is_prefix, is_comprehensive

    return [], False, True


def node_to_prefixes(node, max_possibilities, parser):
    """Convert a node to its potential literal prefixes."""
    is_comprehensive = True

    if node.op == parser.LITERAL:
        # Single literal character
        return [node.value], True, is_comprehensive

    if node.op == parser.IN:
        # Character class
        if len(node.value) > max_possibilities:
            return [], False, is_comprehensive
        return node.value, True, is_comprehensive

    if node.op == parser.SUBPATTERN:
        # Process children nodes sequentially, just like we do for ROOT nodes
        prefixes = [""]
        total_possibilities = 1
        is_fixed_prefix = True

        for child in node.children:
            # Get potential prefixes for this child
            child_prefixes, child_is_prefix, is_comprehensive = node_to_prefixes(
                child, max_possibilities // total_possibilities, parser
            )

            # If this child isn't a prefix generator, we're done collecting
            if not child_is_prefix:
                is_fixed_prefix = False
                break

            # If this would create too many possibilities
            if not child_prefixes or (
                len(child_prefixes) * total_possibilities > max_possibilities
            ):
                # If we already have something, return what we've built so far
                if prefixes != [""]:
                    return prefixes, True, is_comprehensive
                # Otherwise, we can't extract a useful prefix
                return [], False, is_comprehensive

            # Combine current prefixes with child prefixes
            new_prefixes = []
            for prefix in prefixes:
                for child_prefix in child_prefixes:
                    new_prefixes.append(prefix + child_prefix)

            prefixes = new_prefixes
            total_possibilities *= len(child_prefixes)

            # If the set of child prefixes returned was not comprehensive, we can't keep going
            if not is_comprehensive:
                is_comprehensive = False
                break

        return prefixes, is_fixed_prefix, is_comprehensive

    if node.op == parser.BRANCH:
        # Alternation - collect prefixes from all branches
        all_prefixes = []
        all_are_prefixes = True

        for branch in node.children:
            branch_prefixes, is_prefix, branch_is_comprehensive = extract_prefix_from_tree(
                branch, max_possibilities, 0, parser
            )

            # If any of the branch prefixes aren't comprehensive, we can't be comprehensive
            if not branch_is_comprehensive:
                is_comprehensive = False

            if not is_prefix:
                all_are_prefixes = False

            all_prefixes.extend(branch_prefixes)

        if len(all_prefixes) > max_possibilities:
            return [], False, is_comprehensive

        return all_prefixes, all_are_prefixes, is_comprehensive

    if node.op == parser.MAX_REPEAT:
        # Repetition
        min_count, max_count = node.value

        # Get prefixes for the repeated content
        sub_tree = node.children[0]
        sub_prefixes, is_prefix, sub_is_comprehensive = extract_prefix_from_tree(
            sub_tree, max_possibilities, 0, parser
        )

        if not is_prefix or not sub_prefixes:
            return [], False, is_comprehensive

        # If max_count is infinite, bound it to the minimum since there's no point in going futher
        # later parts of the pattern can't safely add anything to the prefixes returned anyway
        if str(max_count) == "MAXREPEAT":
            max_count = min_count
            is_comprehensive = False

        # Create the list of prefixes
        prefixes = []

        # If min_count is 0, then the empty prefix will be included (the empty prefix on its own doesn't bring us closer to max_possibilities)
        # Otherwise we'll build up the guaranteed prefix as close to min_count repetitions as possible
        guaranteed_prefixes = [""]
        # If the subtree is comprehensive, we can build up the guaranteed prefixes
        if sub_is_comprehensive:
            for _ in range(min_count):
                new_prefixes = []
                for prefix in guaranteed_prefixes:
                    for sub_prefix in sub_prefixes:
                        new_prefixes.append(prefix + sub_prefix)
                # If we exceed the max possibilities, flag as not comprehensive and break
                if len(new_prefixes) > max_possibilities:
                    is_comprehensive = False
                    break
                # Adding this additional repetition stays within the max possibilities
                guaranteed_prefixes = new_prefixes
        else:
            # If the subtree is not comprehensive, we can only add the prefixes as they are
            guaranteed_prefixes = sub_prefixes
            is_comprehensive = False
        prefixes.extend(guaranteed_prefixes)

        # Next, we can try to insert additional prefix variations up to the max if the prefixes will still be comprehensive
        # If we can reach the max, the additional prefixes can be included
        # Otherwise, there is no point in adding them and we should set is_comprehensive to False
        if is_comprehensive:
            not_guaranteed_prefixes = []
            prev_new_prefixes = prefixes
            for _ in range(max_count - min_count):
                new_prefixes = []
                for prefix in prev_new_prefixes:
                    for sub_prefix in sub_prefixes:
                        new_prefixes.append(prefix + sub_prefix)
                # If we exceed the max possibilities, flag as not comprehensive and break
                if (
                    len(new_prefixes) + len(not_guaranteed_prefixes) + len(prefixes)
                    > max_possibilities
                ):
                    is_comprehensive = False
                    break
                not_guaranteed_prefixes.extend(new_prefixes)
                prev_new_prefixes = new_prefixes
            # Adding these additional repetitions will stay within the max possibilities if its still comprehensive
            if is_comprehensive:
                prefixes.extend(not_guaranteed_prefixes)

        return prefixes, True, is_comprehensive

    # Any other type of node breaks a fixed prefix
    return [], False, is_comprehensive


def extract_internal_literals(node, max_possibilities, min_length, parser):
    """
    Extract fixed internal literals from the regex tree.
    This function identifies internal sequences that must always be present.
    """
    if node.op == "ROOT":
        # First, try to find fixed literals at the top level
        candidates = []

        # Look for consecutive LITERAL nodes
        current_literal = ""
        for child in node.children:
            if child.op == parser.LITERAL:
                current_literal += child.value
            else:
                if len(current_literal) >= min_length:
                    candidates.append(current_literal)
                current_literal = ""

                # Recursively check this non-literal node
                child_literals = extract_internal_literals(
                    child, max_possibilities, min_length, parser
                )
                candidates.extend(child_literals)

        # Check the last literal sequence
        if len(current_literal) >= min_length:
            candidates.append(current_literal)

        # Remove duplicates while preserving order
        seen = set()
        unique_literals = []
        for literal in candidates:
            if literal not in seen:
                seen.add(literal)
                unique_literals.append(literal)

        return unique_literals[:max_possibilities]

    if node.op == parser.SUBPATTERN:
        # Check inside subpatterns
        return extract_internal_literals(
            RegexNode("ROOT", children=node.children), max_possibilities, min_length, parser
        )

    if node.op == parser.BRANCH:
        # For branches, find literals common to all alternatives
        common_literals = []

        for branch in node.children:
            branch_literals = extract_internal_literals(
                branch, max_possibilities, min_length, parser
            )

            # For the first branch, initialize common_literals
            if not common_literals and branch_literals:
                common_literals = branch_literals
            else:
                # Keep only literals that appear in all branches
                common_literals = [
                    lit for lit in common_literals if any(lit in b_lit for b_lit in branch_literals)
                ]

        return common_literals

    if node.op == parser.MAX_REPEAT:
        min_count = node.value[0]

        # Only consider required repetitions
        if min_count > 0:
            sub_tree = node.children[0]
            sub_literals = extract_internal_literals(
                sub_tree, max_possibilities, min_length, parser
            )

            # If always repeated at least once, these literals must be present
            return sub_literals

    return []
