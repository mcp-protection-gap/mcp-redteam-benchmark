"""Mutation operators applied to attack payloads.

Per the proposal scope rule: 3-5 operators per threat class. These operators
are chosen so that the same operator can be applied to text-bearing payloads
across multiple threat classes (tool descriptions, sampling responses,
tool outputs, etc.).
"""
from cym500.redteam.mutations.obfuscation import obfuscate
from cym500.redteam.mutations.paraphrase import paraphrase_canned
from cym500.redteam.mutations.slow_drip import slow_drip
from cym500.redteam.mutations.split_payload import split_payload
from cym500.redteam.mutations.unicode_dressing import unicode_dress

OPERATORS = {
    "obfuscation": obfuscate,
    "paraphrase": paraphrase_canned,
    "slow_drip": slow_drip,
    "split_payload": split_payload,
    "unicode_dressing": unicode_dress,
}

__all__ = ["OPERATORS"]
