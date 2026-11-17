"""Regex-based HTML helpers (stdlib only, no parser dependency).

These are deliberately forgiving: they do not need a valid DOM, they only need
to pull out the parts of an email an attacker can use to hide text.
"""

from __future__ import annotations

import html as html_module
import re
from dataclasses import dataclass

_ANY_TAG = re.compile(r"<[^<>]*>")
_BLOCK_TAG = re.compile(r"<\s*(?:br|/p|/div|/tr|/li|/h[1-6])\b[^<>]*>", re.IGNORECASE)

# Opening tags. "[^<>]*" stops at the next "<", so an unclosed tag can never
# make the regex scan the rest of the document (keeps the scan linear).
_OPENING_TAG = re.compile(r"<(?P<tag>[a-z][a-z0-9]*)\b(?P<attributes>[^<>]*)>", re.IGNORECASE)
_STYLE_ATTRIBUTE = re.compile(r"\bstyle\s*=\s*(?P<quote>[\"'])(?P<style>.*?)(?P=quote)", re.IGNORECASE | re.DOTALL)
_HREF_ATTRIBUTE = re.compile(r"\bhref\s*=\s*(?P<quote>[\"'])(?P<href>.*?)(?P=quote)", re.IGNORECASE | re.DOTALL)
_ANCHOR_OPENING_TAG = re.compile(r"<a\b(?P<attributes>[^<>]*)>", re.IGNORECASE)

# How far past an opening tag we look for its closing tag. Bounding the
# search keeps many unclosed tags from turning into a quadratic scan.
_MAX_ELEMENT_LENGTH = 20_000
_MAX_ANCHOR_TEXT_LENGTH = 2_000

# Style declarations that make text invisible to a human reader.
_HIDING_DECLARATIONS = [
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    # font-size of 0 or 1 (px/pt/em) is unreadable
    re.compile(r"font-size\s*:\s*[01](?:\.0+)?\s*(?:px|pt|em|rem|%)?\s*(?:;|$|!)", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)", re.IGNORECASE),
    re.compile(r"max-height\s*:\s*0", re.IGNORECASE),
]

# "color:" that is not part of "background-color:".
_WHITE_TEXT_COLOR = re.compile(
    r"(?:^|[;\s\"'])color\s*:\s*(?:#fff\b|#ffffff\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    re.IGNORECASE,
)
_ANY_BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*(?P<value>[^;]+)", re.IGNORECASE)
_WHITE_BACKGROUND_VALUE = re.compile(r"#fff\b|#ffffff\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\)", re.IGNORECASE)


@dataclass
class HtmlParts:
    visible_and_hidden_text: str
    hidden_text_fragments: list[str]
    comments: list[str]
    anchors: list[tuple[str, str]]


def strip_tags(html_source: str) -> str:
    with_line_breaks = _BLOCK_TAG.sub("\n", html_source)
    without_tags = _ANY_TAG.sub(" ", with_line_breaks)
    return html_module.unescape(without_tags)


def is_white_on_white(style_value: str) -> bool:
    """White text is only hidden when the background is white or unset (default white)."""
    if not _WHITE_TEXT_COLOR.search(style_value):
        return False
    background_match = _ANY_BACKGROUND.search(style_value)
    if background_match is None:
        return True
    background_value = background_match.group("value")
    return bool(_WHITE_BACKGROUND_VALUE.search(background_value))


def is_hiding_style(style_value: str) -> bool:
    for declaration_pattern in _HIDING_DECLARATIONS:
        if declaration_pattern.search(style_value):
            return True
    return is_white_on_white(style_value)


def remove_blocks(html_source: str, opening_marker: str, closing_marker: str) -> tuple[str, list[str]]:
    """Cut out every opening...closing block (case-insensitive). Returns (remaining html, block contents).

    Uses str.find instead of a lazy regex so an unclosed marker costs one scan, not one per marker.
    """
    lowered_source = html_source.lower()
    kept_pieces: list[str] = []
    removed_contents: list[str] = []
    position = 0
    while True:
        block_start = lowered_source.find(opening_marker, position)
        if block_start == -1:
            kept_pieces.append(html_source[position:])
            break
        kept_pieces.append(html_source[position:block_start])
        content_start = block_start + len(opening_marker)
        block_end = lowered_source.find(closing_marker, content_start)
        if block_end == -1:
            # Unclosed block: everything after it belongs to the block.
            removed_contents.append(html_source[content_start:])
            break
        removed_contents.append(html_source[content_start:block_end])
        position = block_end + len(closing_marker)
    kept_pieces_joined = " ".join(kept_pieces)
    return kept_pieces_joined, removed_contents


def extract_hidden_text(html_source: str) -> list[str]:
    hidden_fragments: list[str] = []
    lowered_source = html_source.lower()
    for tag_match in _OPENING_TAG.finditer(html_source):
        attributes = tag_match.group("attributes")
        if "style" not in attributes.lower():
            continue
        style_match = _STYLE_ATTRIBUTE.search(attributes)
        if style_match is None or not is_hiding_style(style_match.group("style")):
            continue
        # Take the content up to the first matching closing tag. Nested
        # elements of the same name are rare in hidden blocks; good enough here.
        closing_tag = "</" + tag_match.group("tag").lower()
        content_start = tag_match.end()
        search_limit = content_start + _MAX_ELEMENT_LENGTH
        content_end = lowered_source.find(closing_tag, content_start, search_limit)
        if content_end == -1:
            content_end = min(len(html_source), content_start + 5000)
        inner_html = html_source[content_start:content_end]
        inner_text = strip_tags(inner_html).strip()
        if inner_text:
            hidden_fragments.append(inner_text)
    return hidden_fragments


def extract_anchors(html_source: str) -> list[tuple[str, str]]:
    anchors: list[tuple[str, str]] = []
    lowered_source = html_source.lower()
    for anchor_match in _ANCHOR_OPENING_TAG.finditer(html_source):
        href_match = _HREF_ATTRIBUTE.search(anchor_match.group("attributes"))
        if href_match is None:
            continue
        text_start = anchor_match.end()
        text_end = lowered_source.find("</a", text_start, text_start + _MAX_ANCHOR_TEXT_LENGTH)
        if text_end == -1:
            continue
        href_value = html_module.unescape(href_match.group("href")).strip()
        anchor_text = strip_tags(html_source[text_start:text_end]).strip()
        anchors.append((href_value, anchor_text))
    return anchors


def parse_html(html_source: str) -> HtmlParts:
    without_comments, comments = remove_blocks(html_source, "<!--", "-->")
    stripped_comments = [comment.strip() for comment in comments]
    # Outlook conditional comments ("[if mso]") are layout noise, not text.
    readable_comments = [comment for comment in stripped_comments if comment and not comment.startswith("[if")]
    without_scripts, _script_bodies = remove_blocks(without_comments, "<script", "</script")
    without_styles, _style_bodies = remove_blocks(without_scripts, "<style", "</style")
    return HtmlParts(
        visible_and_hidden_text=strip_tags(without_styles),
        hidden_text_fragments=extract_hidden_text(without_styles),
        comments=readable_comments,
        anchors=extract_anchors(without_styles),
    )
