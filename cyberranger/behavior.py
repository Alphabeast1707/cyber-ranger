from cyberranger.genome import BehaviorDescriptor, Genome, TrialResult


def categorize_injection_point(injection_point: str) -> str:
    """Map a specific injection point to coarsened categories defined in config.
    
    Categories: auth_form, search, url_param, file_upload, cookie
    """
    ip_lower = injection_point.lower()
    if any(k in ip_lower for k in ["login", "auth", "user", "pass", "cred"]):
        return "auth_form"
    if any(k in ip_lower for k in ["search", "query", "find", "filter"]):
        return "search"
    if any(k in ip_lower for k in ["upload", "file", "avatar", "doc"]):
        return "file_upload"
    if any(k in ip_lower for k in ["cookie", "session", "token"]):
        return "cookie"
    return "url_param"


def compute_behavior_descriptor(genome: Genome, result: TrialResult) -> BehaviorDescriptor:
    """Compute the 4-tuple BehaviorDescriptor that maps genome to an archive cell (§3)."""
    # 1. VulnClass
    vuln_class = genome.vuln_class

    # 2. Coarsened injection point
    injection_category = categorize_injection_point(genome.injection_point)

    # 3. Evasion technique
    evasion_tech = genome.evasion_technique

    # 4. Detector outcome: "undetected" | "flagged_low_confidence" | "flagged_high_confidence"
    if not result.detector_flagged:
        detector_outcome = "undetected"
    elif result.detector_confidence < 0.7:
        detector_outcome = "flagged_low_confidence"
    else:
        detector_outcome = "flagged_high_confidence"

    return BehaviorDescriptor(
        vuln_class=vuln_class,
        injection_point_category=injection_category,
        evasion_technique=evasion_tech,
        detector_outcome=detector_outcome,
    )
