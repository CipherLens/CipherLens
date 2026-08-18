"""Safe local placeholder; production providers and network are never defaults."""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherLens v2 local pipeline integration")
    parser.add_argument("--synthetic", action="store_true", help="required for this foundation CLI")
    args = parser.parse_args()
    if not args.synthetic:
        parser.error("only --synthetic is enabled in the Batch 6D foundation")
    print("pipeline_v2 synthetic/local mode; no provider, network, or target execution enabled")


if __name__ == "__main__": main()
