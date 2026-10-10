"""Obfuscation operator: encode the payload so simple substring matchers miss it."""
from __future__ import annotations

import base64
import codecs


def obfuscate(text: str, mode: str = "base64") -> str:
    if mode == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if mode == "rot13":
        return codecs.encode(text, "rot_13")
    if mode == "hex":
        return text.encode("utf-8").hex()
    if mode == "reverse":
        return text[::-1]
    raise ValueError(f"unknown obfuscation mode: {mode}")
