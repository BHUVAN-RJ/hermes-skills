"""scan_email: run every detector, then turn signal weights into a 0-10 score."""

from __future__ import annotations

import math
import time

from . import signals as detectors
from .html_extract import HtmlParts, parse_html
from .models import DEFAULT_THRESHOLD, MEDIUM_RISK_FLOOR, ScanResult, Signal
from .normalize import normalized_view, raw_view

# Per-family ceiling on the summed weight, so ten URL-shortener links or five
# override phrases cannot by themselves push an email to 10.
FAMILY_CAPS = {
    # 8.0 (was 7.0): two strong override phrases together ("ignore previous instructions" +
    # "you are now DAN") are an attack even with nothing else in the email.
    detectors.FAMILY_OVERRIDE: 8.0,
    detectors.FAMILY_ROLE_MARKUP: 6.0,
    detectors.FAMILY_EXFILTRATION: 6.0,
    detectors.FAMILY_AGENT_ADDRESSING: 4.0,
    detectors.FAMILY_TOOL_COMMAND: 4.0,
    detectors.FAMILY_HIDDEN: 6.0,
    detectors.FAMILY_ENCODED: 6.0,
    detectors.FAMILY_LINKS: 4.0,
    detectors.FAMILY_URGENCY: 4.0,
    detectors.FAMILY_UNICODE: 4.5,
    detectors.FAMILY_COVERT: 3.5,
}

# Saturation constant of the score curve: score = 10 * (1 - exp(-raw / K)).
# With K = 8 a raw total of 2 -> 2.2, 5 -> 4.6, 7.4 -> 6.0, 12 -> 7.8.
SCORE_SATURATION = 8.0

OBFUSCATED_INSTRUCTION_WEIGHT = 3.0
HIDDEN_INSTRUCTION_WEIGHT = 4.0
DECODED_INSTRUCTION_WEIGHT = 4.0


def family_total(family_signals: list[Signal], family_cap: float) -> float:
    """Strongest signal counts fully, every extra signal in the same family counts half."""
    sorted_weights = sorted((signal.weight for signal in family_signals), reverse=True)
    strongest_weight = sorted_weights[0]
    extra_weight = 0.5 * sum(sorted_weights[1:])
    return min(family_cap, strongest_weight + extra_weight)


def compute_score(found_signals: list[Signal]) -> tuple[float, float, dict[str, float]]:
    """Return (score 0-10, raw total, per-family totals).

    The exponential curve gives diminishing returns: one weak signal stays
    low, while several independent families together approach 10.
    """
    signals_by_family: dict[str, list[Signal]] = {}
    for signal in found_signals:
        signals_by_family.setdefault(signal.family, []).append(signal)
    family_scores: dict[str, float] = {}
    for family_name, family_signals in signals_by_family.items():
        family_cap = FAMILY_CAPS.get(family_name, 4.0)
        family_scores[family_name] = round(family_total(family_signals, family_cap), 3)
    raw_total = sum(family_scores.values())
    saturated_score = 10.0 * (1.0 - math.exp(-raw_total / SCORE_SATURATION))
    capped_score = min(10.0, saturated_score)
    return round(capped_score, 2), round(raw_total, 3), family_scores


def risk_level_for(score: float, threshold: float) -> str:
    if score >= threshold:
        return "high"
    if score >= min(MEDIUM_RISK_FLOOR, threshold):
        return "medium"
    return "low"


def _scan_both_views(text: str) -> tuple[list[Signal], list[Signal]]:
    """Run text rules on raw and normalized views. Returns (hits, normalized-only hits)."""
    raw_hits = detectors.detect_text_rules(raw_view(text))
    normalized_text = normalized_view(text)
    normalized_hits = detectors.detect_text_rules(normalized_text)
    raw_hit_names = {hit.name for hit in raw_hits}
    merged_hits = list(raw_hits)
    normalized_only_hits: list[Signal] = []
    for hit in normalized_hits:
        if hit.name in raw_hit_names:
            continue
        merged_hits.append(hit)
        normalized_only_hits.append(hit)
    has_exfil_request = any(hit.family == detectors.FAMILY_EXFILTRATION for hit in merged_hits)
    if has_exfil_request:
        destination_hit = detectors.detect_exfiltration_destination(normalized_text)
        if destination_hit is not None:
            merged_hits.append(destination_hit)
    urgency_hit = detectors.detect_urgency_with_authority(normalized_text)
    if urgency_hit is not None:
        merged_hits.append(urgency_hit)
    covert_hit = detectors.detect_covert_exfiltration(merged_hits)
    if covert_hit is not None:
        merged_hits.append(covert_hit)
    return merged_hits, normalized_only_hits


def _instruction_hits_in(fragments: list[str]) -> list[Signal]:
    hits: list[Signal] = []
    for fragment in fragments:
        fragment_hits, _normalized_only = _scan_both_views(fragment)
        hits.extend(fragment_hits)
    return [hit for hit in hits if hit.family in detectors.INSTRUCTION_FAMILIES]


def _add_unique(found_signals: list[Signal], new_signals: list[Signal]) -> None:
    """Add signals whose name is not already present (the same rule counts once)."""
    existing_names = {signal.name for signal in found_signals}
    for signal in new_signals:
        if signal.name in existing_names:
            continue
        found_signals.append(signal)
        existing_names.add(signal.name)


def collect_signals(subject: str, body: str, sender: str = "", html: str | None = None) -> list[Signal]:
    html_parts: HtmlParts | None = parse_html(html) if html else None
    # The sender's display name/address can carry authority claims ("CEO <...>").
    text_sections = [sender, subject, body]
    if html_parts is not None:
        # Hidden text and comments are included on purpose: the model sees them.
        text_sections.append(html_parts.visible_and_hidden_text)
        text_sections.extend(html_parts.comments)
    combined_text = "\n".join(section for section in text_sections if section)

    found_signals: list[Signal] = []
    text_hits, normalized_only_hits = _scan_both_views(combined_text)
    _add_unique(found_signals, text_hits)

    # An instruction that only appears after removing zero-width chars,
    # mapping homoglyphs or NFKC folding was deliberately disguised.
    normalized_only_instructions = [hit for hit in normalized_only_hits if hit.family in detectors.INSTRUCTION_FAMILIES]
    if normalized_only_instructions:
        evidence = normalized_only_instructions[0].evidence
        obfuscated_signal = Signal("obfuscated_instruction", detectors.FAMILY_HIDDEN, OBFUSCATED_INSTRUCTION_WEIGHT, evidence)
        _add_unique(found_signals, [obfuscated_signal])

    raw_sources = combined_text
    if html:
        raw_sources = combined_text + "\n" + html

    zero_width_hit = detectors.detect_zero_width_characters(combined_text)
    bidi_hit = detectors.detect_bidi_controls(combined_text)
    mixed_script_hit = detectors.detect_mixed_script_words(combined_text)
    single_hits = [zero_width_hit, bidi_hit, mixed_script_hit]
    _add_unique(found_signals, [hit for hit in single_hits if hit is not None])

    if html_parts is not None:
        hidden_text_hit = detectors.detect_html_hidden_text(html_parts.hidden_text_fragments)
        if hidden_text_hit is not None:
            _add_unique(found_signals, [hidden_text_hit])
        hidden_fragments = html_parts.hidden_text_fragments + html_parts.comments
        hidden_instruction_hits = _instruction_hits_in(hidden_fragments)
        if hidden_instruction_hits:
            evidence = hidden_instruction_hits[0].evidence
            hidden_signal = Signal("hidden_instructions", detectors.FAMILY_HIDDEN, HIDDEN_INSTRUCTION_WEIGHT, evidence)
            _add_unique(found_signals, [hidden_signal])
        # Raw <system> tags are stripped from the visible text, so check the source too.
        raw_markup_hits = detectors.detect_text_rules(raw_view(html), detectors.ROLE_MARKUP_RULES[:3])
        _add_unique(found_signals, raw_markup_hits)

    anchors = html_parts.anchors if html_parts is not None else []
    _add_unique(found_signals, detectors.detect_link_obfuscation(raw_sources, anchors))

    # Decode long base64/hex blobs once and re-scan the decoded text (no recursion).
    decoded_payloads = detectors.find_encoded_text_payloads(raw_sources)
    _add_unique(found_signals, detectors.detect_encoded_payload_signals(decoded_payloads))
    decoded_texts = [decoded_text for _kind, decoded_text in decoded_payloads]
    decoded_instruction_hits = _instruction_hits_in(decoded_texts)
    if decoded_instruction_hits:
        evidence = decoded_instruction_hits[0].evidence
        decoded_signal = Signal("decoded_payload_instructions", detectors.FAMILY_ENCODED, DECODED_INSTRUCTION_WEIGHT, evidence)
        _add_unique(found_signals, [decoded_signal])
        _add_unique(found_signals, decoded_instruction_hits)
    return found_signals


def scan_email(
    subject: str,
    body: str,
    sender: str = "",
    html: str | None = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> ScanResult:
    """Deterministically score an email for prompt-injection risk (0 = clean, 10 = attack)."""
    start_time = time.perf_counter()
    found_signals = collect_signals(subject or "", body or "", sender or "", html)
    score, raw_total, family_scores = compute_score(found_signals) if found_signals else (0.0, 0.0, {})
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return ScanResult(
        score=score,
        risk_level=risk_level_for(score, threshold),
        signals=found_signals,
        flagged=score >= threshold,
        elapsed_ms=round(elapsed_ms, 3),
        threshold=threshold,
        family_scores=family_scores,
        raw_total=raw_total,
    )
