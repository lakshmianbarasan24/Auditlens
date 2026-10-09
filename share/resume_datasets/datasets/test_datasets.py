"""Serves recorded backend responses from the dummy datasets (no API key, no running server).

Each dataset folder in ./datasets holds one JSON file per backend flow. This script only
returns the data exactly as the backend recorded it; it does not judge or score anything.

CLI:
    python test_datasets.py                          # list datasets
    python test_datasets.py dataset_a                # list flows in a dataset
    python test_datasets.py dataset_a login          # all exchanges for a flow
    python test_datasets.py dataset_a login 1        # one exchange (0-based index)
    python test_datasets.py dataset_a login --body   # response bodies only

Python:
    from test_datasets import list_datasets, list_flows, get_exchanges, get_response
    get_response("dataset_a", "evaluate", 0)   # {"status": 200, "headers": {...}, "body": {...}}
"""
import json
import sys
from pathlib import Path
from typing import Any

DATASETS_DIR = Path(__file__).resolve().parent / "datasets"


def list_datasets() -> list[str]:
    return sorted(p.name for p in DATASETS_DIR.iterdir() if p.is_dir())


def list_flows(dataset: str) -> list[str]:
    return sorted(p.stem for p in _dataset_dir(dataset).glob("*.json"))


def get_exchanges(dataset: str, flow: str) -> list[dict[str, Any]]:
    """Every recorded exchange for a flow: [{"request": {...}, "response": {...}}, ...]."""
    path = _dataset_dir(dataset) / f"{flow}.json"
    if not path.exists():
        raise KeyError(f"Unknown flow '{flow}' in {dataset}. Available: {', '.join(list_flows(dataset))}")
    return json.loads(path.read_text(encoding="utf-8"))["exchanges"]


def get_response(dataset: str, flow: str, index: int = 0) -> dict[str, Any]:
    """The recorded response (status, headers, body) of one exchange."""
    exchanges = get_exchanges(dataset, flow)
    if not 0 <= index < len(exchanges):
        raise IndexError(f"{flow} has {len(exchanges)} exchange(s); index {index} is out of range")
    item = exchanges[index]
    return item.get("response", item)


def _dataset_dir(dataset: str) -> Path:
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
        elif len(args) == 1:
            print("\n".join(list_flows(args[0])))
        else:
            exchanges = get_exchanges(args[0], args[1])
            if len(args) > 2:
                exchanges = [exchanges[int(args[2])]]
            if body_only:
                exchanges = [e.get("response", e).get("body", e) for e in exchanges]
            print(json.dumps(exchanges, indent=2))
    except (KeyError, IndexError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
