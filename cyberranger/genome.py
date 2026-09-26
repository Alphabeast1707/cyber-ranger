from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional
import uuid


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    # extend as your DVWA config's modules grow


class EvasionTechnique(str, Enum):
    NONE = "none"
    ENCODING = "encoding"          # url/hex/unicode encoding
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_SUBSTITUTION = "whitespace_substitution"
    SEMANTIC_REWRITE = "semantic_rewrite"  # LLM-proposed, not in the fixed enum above —
                                            # store the actual technique name as free text
                                            # when this value is used


@dataclass
class Genome:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)
    operator_used: str = ""          # "grammar" | "crossover" | "llm_semantic"
    vuln_class: VulnClass = VulnClass.SQLI
    injection_point: str = ""        # e.g. "login.username", "search.query_param"
    evasion_technique: EvasionTechnique = EvasionTechnique.NONE
    evasion_technique_detail: Optional[str] = None  # free text for LLM-proposed techniques
    payload_template: str = ""       # abstract structure, not the literal string
    rendered_payload: str = ""       # the literal string actually sent
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["vuln_class"] = self.vuln_class.value if isinstance(self.vuln_class, VulnClass) else str(self.vuln_class)
        data["evasion_technique"] = (
            self.evasion_technique.value
            if isinstance(self.evasion_technique, EvasionTechnique)
            else str(self.evasion_technique)
        )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Genome":
        payload = dict(data)
        if "vuln_class" in payload and isinstance(payload["vuln_class"], str):
            payload["vuln_class"] = VulnClass(payload["vuln_class"])
        if "evasion_technique" in payload and isinstance(payload["evasion_technique"], str):
            payload["evasion_technique"] = EvasionTechnique(payload["evasion_technique"])
        return cls(**payload)


@dataclass
class TrialResult:
    genome_id: str
    target_compromised: bool
    compromise_confidence: float     # 0-1, from response-diff heuristics
    detector_flagged: bool
    detector_confidence: float       # 0-1, from blue detector's own score
    detector_rule_fired: Optional[str]
    response_signature: str          # hashable fingerprint of the raw response, for dedup
    latency_ms: int
    raw_response_excerpt: str        # truncated, for triage review only

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrialResult":
        return cls(**data)


@dataclass
class BehaviorDescriptor:
    """The tuple that determines which archive cell a genome belongs to."""
    vuln_class: VulnClass
    injection_point_category: str    # coarsened injection_point, e.g. "auth_form" | "search" | "url_param"
    evasion_technique: EvasionTechnique
    detector_outcome: str            # "undetected" | "flagged_low_confidence" | "flagged_high_confidence"

    def cell_key(self) -> tuple:
        return (self.vuln_class, self.injection_point_category,
                self.evasion_technique, self.detector_outcome)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class.value if isinstance(self.vuln_class, VulnClass) else str(self.vuln_class),
            "injection_point_category": self.injection_point_category,
            "evasion_technique": (
                self.evasion_technique.value
                if isinstance(self.evasion_technique, EvasionTechnique)
                else str(self.evasion_technique)
            ),
            "detector_outcome": self.detector_outcome,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BehaviorDescriptor":
        payload = dict(data)
        if "vuln_class" in payload and isinstance(payload["vuln_class"], str):
            payload["vuln_class"] = VulnClass(payload["vuln_class"])
        if "evasion_technique" in payload and isinstance(payload["evasion_technique"], str):
            payload["evasion_technique"] = EvasionTechnique(payload["evasion_technique"])
        return cls(**payload)
