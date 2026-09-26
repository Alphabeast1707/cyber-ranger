import math
from typing import Sequence


class OperatorBandit:
    """UCB1 multi-armed bandit for mutation operator selection (§4)."""

    def __init__(self, arms: Sequence[str]):
        self.arms = list(arms)
        self.counts = {a: 0 for a in self.arms}
        self.total_reward = {a: 0.0 for a in self.arms}
        self.t = 0

    def select(self) -> str:
        self.t += 1
        # play every arm once first
        for a in self.arms:
            if self.counts[a] == 0:
                return a

        def ucb(a: str) -> float:
            mean = self.total_reward[a] / self.counts[a]
            bonus = math.sqrt(2.0 * math.log(self.t) / self.counts[a])
            return mean + bonus

        return max(self.arms, key=ucb)

    def update(self, arm: str, reward: float):
        """reward should be: 1.0 for a new archive cell, 0.3 for beating an
        incumbent, 0.0 for no archive improvement. Clip to [0, 1]."""
        if arm not in self.counts:
            self.arms.append(arm)
            self.counts[arm] = 0
            self.total_reward[arm] = 0.0

        clipped_reward = max(0.0, min(1.0, float(reward)))
        self.counts[arm] += 1
        self.total_reward[arm] += clipped_reward

    def mean_reward(self, arm: str) -> float:
        if self.counts.get(arm, 0) == 0:
            return 0.0
        return self.total_reward[arm] / self.counts[arm]

    def arm_weights(self) -> dict[str, float]:
        """Return the current mean reward per arm (or 0.0 if unplayed)."""
        return {a: self.mean_reward(a) for a in self.arms}

    def selection_distribution(self) -> dict[str, float]:
        """Return the fraction of times each arm has been pulled."""
        if self.t == 0:
            return {a: 0.0 for a in self.arms}
        return {a: self.counts[a] / self.t for a in self.arms}
