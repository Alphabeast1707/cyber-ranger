"""Run regression suite against historical red elites and blue snapshots (§11)."""

import argparse
from pathlib import Path

from cyberranger.orchestrator import Orchestrator, OrchestratorConfig

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


def main():
    parser = argparse.ArgumentParser(description="CyberRanger Regression Pass")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config file")
    args = parser.parse_args()

    cfg = OrchestratorConfig.from_yaml(args.config)
    orchestrator = Orchestrator(cfg)
    orchestrator.regression_pass()
    print("[CyberRanger] Regression pass complete.")


if __name__ == "__main__":
    main()
