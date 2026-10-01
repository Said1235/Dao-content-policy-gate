"""Shared helpers for direct mode tests."""
import os

import pytest


def to_hex(addr_bytes):
    """Convert address bytes to the checksummed hex the contract returns via Address.as_hex."""
    if hasattr(addr_bytes, "as_hex"):
        return addr_bytes.as_hex
    from genlayer.py.types import Address

    return Address(addr_bytes).as_hex


# ---------------------------------------------------------------------------------------------
# TEST-ONLY patch for variant B (new-generation SDK) with genlayer-test 0.30.0rc2.
#
# Root cause (confirmed by reading the installed code, gltest/direct/wasi_mock.py):
#   `_handle_llm_request` auto-parses the mocked JSON string into a `dict` before returning it. The
#   new-generation SDK (`genlayer.nondet._decode_nondet_json`) requires the RAW TEXT and runs
#   `json.loads` itself, so a dict fails with "JSON result is not text". This is a bug of the test
#   tool, not of the contract. The patch returns the text untouched ONLY when testing variant B.
#   It does not modify the contract nor the installed package.
# ---------------------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _raw_llm_text_for_new_generation(monkeypatch):
    if not os.environ.get("GATE_CONTRACT", "").endswith("_v2.py"):
        yield
        return
    from gltest.direct import wasi_mock

    original = wasi_mock._handle_llm_request

    def raw_text_handler(vm, data):
        response = vm._match_llm_mock(data.get("prompt", ""))
        if response is not None:
            return {"ok": response}  # raw text: the new SDK parses it
        return original(vm, data)  # no mock: original behaviour (strict / live)

    monkeypatch.setattr(wasi_mock, "_handle_llm_request", raw_text_handler)
    yield
