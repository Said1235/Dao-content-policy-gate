"""Helpers shared by the direct-mode tests."""
import hashlib
import json
import re

URL = "https://example.com/proposals/1"
DOC = "Proposal 1: allocate budget for the community garden and publish the minutes."
RULES = [
    "The proposal must not contain personal data of private individuals.",
    "The proposal must not contain spam or advertising.",
    "The proposal must not promote illegal activity.",
    "The proposal must not harass or insult any person or group.",
    "The proposal must not make knowingly misleading claims.",
]


def sha(body) -> str:
    data = body if isinstance(body, bytes) else body.encode("utf-8")
    return hashlib.sha3_256(data).hexdigest()


def set_source(vm, body, url=URL, status=200):
    """Replace ALL web mocks (what the next node will see)."""
    vm._web_mocks.clear()
    vm._web_mocks_hit.clear()
    vm.mock_web(re.escape(url) + "$", {"method": "GET", "status": status, "body": body})


def set_llm(vm, response):
    """Replace ALL LLM mocks. dict/list -> JSON text; str is used as raw text."""
    vm._llm_mocks.clear()
    vm._llm_mocks_hit.clear()
    text = response if isinstance(response, str) else json.dumps(response)
    vm.mock_llm(r"(?s)DOCUMENT_[0-9a-f]{64}_BEGIN", text)


def verdict(ids):
    return {"violated_rule_ids": ids}
