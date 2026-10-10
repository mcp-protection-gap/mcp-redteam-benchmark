"""Decorate the payload with zero-width and direction-control characters.

This operator is used to test whether gateways normalise Unicode before
matching. If they do not, this often defeats simple substring rules without
changing the rendered text the LLM ultimately sees.
"""
from __future__ import annotations

ZWSP = "​"
ZWJ = "‍"
LRO = "‭"
PDF = "‬"


def unicode_dress(text: str, mode: str = "interspersed_zwsp") -> str:
    if mode == "interspersed_zwsp":
        return ZWSP.join(text)
    if mode == "wrapped_lro":
        return f"{LRO}{text}{PDF}"
    if mode == "leading_bom":
        return "﻿" + text
    raise ValueError(f"unknown unicode mode: {mode}")
