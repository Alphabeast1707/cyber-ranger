"""Run the generation loop (§11)."""

import argparse
from pathlib import Path

from cyberranger.orchestrator import Orchestrator, OrchestratorConfig

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


def main():
    parser = argparse.ArgumentParser(description="CyberRanger Generation Loop")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config file")
    parser.add_argument("--generations", type=int, default=5, help="Number of generations to run")
    args = parser.parse_args()

    cfg = OrchestratorConfig.from_yaml(args.config)
    orchestrator = Orchestrator(cfg)
    orchestrator.run(max_generations=args.generations)


if __name__ == "__main__":
    main()
