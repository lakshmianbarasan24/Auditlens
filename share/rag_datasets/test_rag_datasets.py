"""Serves recorded data of the support-ticket RAG chatbot (no API key, no server).

Datasets live in this folder (rag_a, rag_b; one JSON file per flow). This script only
returns the recorded data exactly as it was captured; it does not analyse or score anything.

CLI:
    python test_rag_datasets.py                          list datasets
    python test_rag_datasets.py profile                  what this application is (roles, flows, policies)
    python test_rag_datasets.py rag_a                list flows in a dataset
    python test_rag_datasets.py rag_a login          all exchanges of a flow
    python test_rag_datasets.py rag_a login 1        one exchange (0-based index)
    python test_rag_datasets.py rag_a login --body   response bodies only

Python:
    from test_datasets import (list_datasets, list_flows, get_exchanges,
                               get_response, get_application_profile)
"""
import json
import sys
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
DATASETS_DIR = PACKAGE_DIR
PROFILE_FILE = PACKAGE_DIR / "application_profile.json"


def get_application_profile() -> dict[str, Any]:
    """What this application is: purpose, roles, components, flows, stated policies."""
    return json.loads(PROFILE_FILE.read_text(encoding="utf-8"))


def list_datasets() -> list[str]:
    return sorted(p.name for p in DATASETS_DIR.iterdir() if p.is_dir() and p.name.startswith("rag_"))


def list_flows(dataset: str) -> list[str]:
    return sorted(p.stem for p in _rag_dir(dataset).glob("*.json"))


def get_exchanges(dataset: str, flow: str) -> list[dict[str, Any]]:
    """Every recorded item of a flow, e.g. [{"request": {...}, "response": {...}}, ...]."""
    path = _rag_dir(dataset) / f"{flow}.json"
    if not path.exists():
        raise KeyError(f"Unknown flow '{flow}' in {dataset}. Available: {', '.join(list_flows(dataset))}")
    return json.loads(path.read_text(encoding="utf-8"))["exchanges"]


def get_response(dataset: str, flow: str, index: int = 0) -> dict[str, Any]:
    """One item of a flow: its recorded response (status, headers, body), or the item itself."""
    exchanges = get_exchanges(dataset, flow)
    if not 0 <= index < len(exchanges):
        raise IndexError(f"{flow} has {len(exchanges)} item(s); index {index} is out of range")
    item = exchanges[index]
    return item.get("response", item)


def _rag_dir(dataset: str) -> Path:
    path = DATASETS_DIR / dataset
    if not path.is_dir():
        raise KeyError(f"Unknown dataset '{dataset}'. Available: {', '.join(list_datasets())}")
    return path


def main(argv: list[str]) -> int:
    body_only = "--body" in argv
    args = [a for a in argv if a != "--body"]
    try:
        if not args:
            print("\n".join(list_datasets()))
        elif args == ["profile"]:
            print(json.dumps(get_application_profile(), indent=2))
        elif len(args) == 1:
            print("\n".join(list_flows(args[0])))
        else:
            items = get_exchanges(args[0], args[1])
            if len(args) > 2:
                items = [items[int(args[2])]]
            if body_only:
                items = [i.get("response", i).get("body", i) for i in items]
            print(json.dumps(items, indent=2))
    except (KeyError, IndexError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
