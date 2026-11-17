"""Result types shared by the scanner, the wrapper and the CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

DEFAULT_THRESHOLD = 6.0
MEDIUM_RISK_FLOOR = 3.0


@dataclass(frozen=True)
class Signal:
    """One piece of evidence that the email may contain a prompt injection."""

    name: str
    family: str
    weight: float
    evidence: str = ""


@dataclass
class ScanResult:
    """Outcome of scanning one email. Higher score means more suspicious."""

    score: float
    risk_level: str
    signals: list[Signal]
    flagged: bool
    elapsed_ms: float
    threshold: float = DEFAULT_THRESHOLD
    family_scores: dict[str, float] = field(default_factory=dict)
    raw_total: float = 0.0

    @property
    def signal_names(self) -> list[str]:
        return [signal.name for signal in self.signals]

    def to_dict(self) -> dict:
        result_dict = asdict(self)
        result_dict["signal_names"] = self.signal_names
        return result_dict
