"""Build the red-team corpus from registered Attack classes."""
from __future__ import annotations

import json
from pathlib import Path

from cym500.common.logging import get_logger
from cym500.common.storage import DATA_ROOT
from cym500.redteam.attacks import ATTACK_CLASSES

log = get_logger(__name__)

OUT = Path(DATA_ROOT) / "processed" / "redteam_corpus.jsonl"


def build() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with OUT.open("w") as f:
        for cls in ATTACK_CLASSES:
            attack = cls()
            for case in attack.cases():
                f.write(
                    json.dumps(
                        {
                            "case_id": case.case_id,
                            "threat_class": case.threat_class.value,
                            "variant_id": case.variant_id,
                            "target": case.target.value,
                            "payload": case.payload,
                            "description": case.description,
                            "expected_outcome": case.expected_outcome,
                            "derived_from": case.derived_from,
                            "metadata": case.metadata,
                        }
                    )
                    + "\n"
                )
                n += 1
    log.info("redteam_corpus_built", n=n, path=str(OUT))
    return n
