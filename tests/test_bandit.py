"""Tests for Milestone 5 (§14):
- OperatorBandit algorithm (§4)
- Wiring to archive rewards (§8)
- Confirming arm weights shift when an operator is artificially crippled
"""

import pytest

from cyberranger.archive import Archive
from cyberranger.genome import BehaviorDescriptor, EvasionTechnique, Genome, TrialResult, VulnClass
from cyberranger.operators.bandit import OperatorBandit


def test_bandit_initial_round_robin():
    """Verify bandit plays every arm once before using UCB exploitation."""
    arms = ["grammar", "crossover", "llm_semantic"]
    bandit = OperatorBandit(arms)

    pulled_arms = []
    for _ in range(len(arms)):
        arm = bandit.select()
        pulled_arms.append(arm)
        bandit.update(arm, 0.5)

    assert set(pulled_arms) == set(arms)


def test_bandit_reward_clipping_and_mean():
    """Verify rewards are clipped to [0, 1] and mean rewards compute accurately."""
    bandit = OperatorBandit(["arm1", "arm2"])
    bandit.update("arm1", 1.5)  # Should clip to 1.0
    bandit.update("arm1", 0.5)
    bandit.update("arm2", -1.0)  # Should clip to 0.0

    assert bandit.counts["arm1"] == 2
    assert bandit.total_reward["arm1"] == 1.5
    assert bandit.mean_reward("arm1") == 0.75
    assert bandit.mean_reward("arm2") == 0.0


def test_bandit_arm_weights_shift_when_crippled():
    """Confirm arm weights shift dramatically when one operator is artificially crippled (§14 Milestone 5)."""
    arms = ["grammar", "crossover", "llm_semantic"]
    bandit = OperatorBandit(arms)

    # Run for 120 trials:
    # - grammar produces reward 1.0 (new_cell)
    # - crossover produces reward 0.3 (replaced_incumbent)
    # - llm_semantic is crippled: produces reward 0.0 (rejected)
    reward_map = {
        "grammar": 1.0,
        "crossover": 0.3,
        "llm_semantic": 0.0,
    }

    for _ in range(120):
        arm = bandit.select()
        reward = reward_map[arm]
        bandit.update(arm, reward)

    weights = bandit.arm_weights()
    counts = bandit.counts

    # Grammar should have highest weight and highest pull count
    assert weights["grammar"] == 1.0
    assert weights["crossover"] == pytest.approx(0.3)
    assert weights["llm_semantic"] == 0.0

    assert counts["grammar"] > counts["crossover"]
    assert counts["crossover"] > counts["llm_semantic"]
    assert counts["grammar"] > counts["llm_semantic"] * 3, (
        f"Crippled arm was not suppressed enough: counts={counts}"
    )


def test_bandit_wired_to_archive_rewards():
    """Simulate bandit loop wired directly to Archive.try_insert rewards."""
    archive = Archive()
    bandit = OperatorBandit(["effective_arm", "crippled_arm"])

    # Simulate 50 steps
    for step in range(50):
        arm = bandit.select()

        # Create dummy genome & trial result
        g = Genome(vuln_class=VulnClass.SQLI, operator_used=arm)
        tr = TrialResult(
            genome_id=g.id,
            target_compromised=True,
            compromise_confidence=0.8,
            detector_flagged=False,
            detector_confidence=0.0,
            detector_rule_fired=None,
            response_signature=f"sig_{step}",
            latency_ms=10,
            raw_response_excerpt="ok",
        )

        if arm == "effective_arm":
            # Discovers a new distinct cell each time
            descriptor = BehaviorDescriptor(
                vuln_class=VulnClass.SQLI,
                injection_point_category=f"cat_{step}",
                evasion_technique=EvasionTechnique.NONE,
                detector_outcome="undetected",
            )
            fitness = 0.8
        else:
            # Always collides in cell with zero improvement -> rejected
            descriptor = BehaviorDescriptor(
                vuln_class=VulnClass.SQLI,
                injection_point_category="always_same",
                evasion_technique=EvasionTechnique.NONE,
                detector_outcome="undetected",
            )
            fitness = 0.01

        outcome = archive.try_insert(g, tr, descriptor, fitness)
        reward = {"new_cell": 1.0, "replaced_incumbent": 0.3, "rejected": 0.0}[outcome]
        bandit.update(arm, reward)

    weights = bandit.arm_weights()
    assert weights["effective_arm"] > weights["crippled_arm"]
    assert bandit.counts["effective_arm"] > bandit.counts["crippled_arm"]
