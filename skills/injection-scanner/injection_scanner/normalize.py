"""Text normalization so obfuscated phrases look like their plain form."""

from __future__ import annotations

import re
import unicodedata

# Invisible characters an attacker can put inside a word ("ig\u200bnore") so a
# naive regex no longer matches it, while the model still reads the word.
ZERO_WIDTH_CHARACTERS = "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"

# Bidirectional embedding/override/isolate controls. They reorder how text is
# displayed, so a human reviewer sees something different from what the model gets.
BIDI_CONTROL_CHARACTERS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

# Lowercase Cyrillic and Greek letters that render the same as Latin letters.
# Mapping them back lets "іgnоre" (Cyrillic i and o) match "ignore".
_CONFUSABLE_TO_LATIN = {
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic ie
    "о": "o",  # Cyrillic o
    "р": "p",  # Cyrillic er
    "с": "c",  # Cyrillic es
    "у": "y",  # Cyrillic u
    "х": "x",  # Cyrillic ha
    "і": "i",  # Cyrillic byelorussian-ukrainian i
    "ј": "j",  # Cyrillic je
    "ѕ": "s",  # Cyrillic dze
    "ԁ": "d",  # Cyrillic komi de
    "һ": "h",  # Cyrillic shha
    "ο": "o",  # Greek omicron
    "α": "a",  # Greek alpha
    "ε": "e",  # Greek epsilon
    "ι": "i",  # Greek iota
    "ν": "v",  # Greek nu
    "ρ": "p",  # Greek rho
    "κ": "k",  # Greek kappa
    "τ": "t",  # Greek tau
}

_INVISIBLE_REMOVAL_TABLE = {ord(char): None for char in ZERO_WIDTH_CHARACTERS + BIDI_CONTROL_CHARACTERS}
_CONFUSABLE_TABLE = {ord(char): latin for char, latin in _CONFUSABLE_TO_LATIN.items()}

# Collapse runs of spaces and tabs but keep newlines, so line-anchored
# patterns such as "### System:" still work after normalization.
_HORIZONTAL_WHITESPACE = re.compile(r"[ \t\r\f\v ]+")


def collapse_whitespace(text: str) -> str:
    return _HORIZONTAL_WHITESPACE.sub(" ", text)


def raw_view(text: str) -> str:
    """Lowercased text with nothing else removed: what a naive filter would see."""
    lowered_text = text.lower()
    return collapse_whitespace(lowered_text)


def normalized_view(text: str) -> str:
    """NFKC + lowercase + invisible characters removed + homoglyphs mapped to Latin."""
    compatibility_folded = unicodedata.normalize("NFKC", text)
    lowered_text = compatibility_folded.lower()
    without_invisibles = lowered_text.translate(_INVISIBLE_REMOVAL_TABLE)
    latin_mapped = without_invisibles.translate(_CONFUSABLE_TABLE)
    return collapse_whitespace(latin_mapped)
