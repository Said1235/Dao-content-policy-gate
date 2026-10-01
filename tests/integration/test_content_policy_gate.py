"""Integration tests: need a GenLayer network with several validators (GLSim or Studio).

Needs a GenLayer network with validators (Studio, or GLSim). Not run on Studio by the author.

  # variant A (runner 1jb45..., genlayer-test 0.29.x)
  GATE_CONTRACT=contracts/content_policy_gate.py    gltest tests/integration/ -v -s --network <network>
  # variant B (runner 5jycge..., Studio v0.123.0-rc.x, genlayer-test 0.30.x)
  GATE_CONTRACT=contracts/content_policy_gate_v2.py gltest tests/integration/ -v -s --network <network>

Use a commit-pinned URL: `source_hash` identifies the audited bytes, not the URL.
"""
import hashlib
import json
import os

import pytest
import requests
from eth_utils import to_checksum_address
from gltest import get_contract_factory, get_default_account
from gltest.assertions import tx_execution_failed, tx_execution_succeeded
from gltest.contracts.contract import Contract

# gltest resolves contract_file_path RELATIVE to the contracts/ directory
CONTRACT_FILE = os.environ.get("GATE_CONTRACT", "contracts/content_policy_gate.py").removeprefix("contracts/")
URL = (
    "https://raw.githubusercontent.com/genlayerlabs/genlayer-project-boilerplate/"
    "e685f1f12c4c357787d48390692a654baf576f03/README.md"
)
RULES = [
    "The proposal must not contain spam or advertising.",
    "The proposal must not promote illegal activity.",
    "The proposal must not harass or insult any person or group.",
]
WAIT = dict(wait_interval=10000, wait_retries=30)


def expected_audit_id(proposal_id, nonce):
    """Independent derivation from the specification (not by calling the contract's own view):
    sha3_256(json(["gate-audit-v1", requester, proposal_id, request_nonce]))."""
    requester = to_checksum_address(get_default_account().address)
    return hashlib.sha3_256(json.dumps(["gate-audit-v1", requester, proposal_id, nonce]).encode("utf-8")).hexdigest()


def read(result):
    """Views: gltest 0.29.2 returns a ContractFunction (.call()); the boilerplate's style returns the value."""
    return result.call() if hasattr(result, "call") else result


def write(result):
    """Writes: gltest 0.29.2 returns a ContractFunction (.transact()); the boilerplate's style returns the receipt."""
    return result.transact(**WAIT) if hasattr(result, "transact") else result


@pytest.fixture(scope="module")
def gate():
    factory = get_contract_factory(contract_file_path=CONTRACT_FILE)
    contract = factory.deploy(args=[])  # deploy WITHOUT data
    if not hasattr(contract, "get_policy"):
        # GLSim 0.29.x quirk (it also happens with the boilerplate's football_bets): the running simulator
        # answers schema requests with an EMPTY schema once the class is deployed, and asking for the
        # schema before deploying breaks the deployment itself. gltest then builds no methods. Workaround:
        # take the schema from an independent in-process engine and rebuild the Contract object.
        # On Studio the methods already exist and this block is skipped.
        from glsim.engine import SimEngine
        from glsim.state import StateStore

        schema = SimEngine(StateStore()).get_sdk_schema_for_code(factory.contract_code.encode("utf-8"))
        contract = Contract.new(address=contract.address, schema=schema, account=contract.account)
    assert read(contract.get_policy(args=[])) == {"initialized": False, "policy_version": "", "rules": []}
    return contract


def test_01_uninitialized_gate_rejects_audits(gate):
    result = write(gate.request_audit(args=["prop-0", URL, "n0"]))
    assert tx_execution_failed(result)
    assert read(gate.has_audit(args=[expected_audit_id("prop-0", "n0")])) is False


def test_02_initialize_policy_once(gate):
    assert tx_execution_succeeded(write(gate.initialize_policy(args=["policy-v1", json.dumps(RULES)])))
    assert read(gate.get_policy(args=[])) == {"initialized": True, "policy_version": "policy-v1", "rules": RULES}
    assert tx_execution_failed(write(gate.initialize_policy(args=["policy-v2", json.dumps(RULES[:1])])))
    assert read(gate.get_policy(args=[]))["policy_version"] == "policy-v1"


def test_03_audit_binds_source_hash_and_derives_status(gate):
    assert tx_execution_succeeded(write(gate.request_audit(args=["prop-1", URL, "n1"])))
    audit_id = expected_audit_id("prop-1", "n1")
    rec = read(gate.get_audit(args=[audit_id]))
    body = requests.get(URL, timeout=20).content
    assert rec["source_hash"] == hashlib.sha3_256(body).hexdigest()  # commitment over the real bytes
    assert rec["policy_version"] == "policy-v1" and rec["proposal_url"] == URL
    assert rec["status"] == ("COMPLIANT" if rec["violated_rule_ids"] == [] else "NON_COMPLIANT")
    assert rec["violated_rule_ids"] == sorted(set(rec["violated_rule_ids"]))
    assert all(1 <= i <= len(RULES) for i in rec["violated_rule_ids"])


def test_04_same_nonce_rejected_and_new_nonce_creates_separate_audit(gate):
    a1 = expected_audit_id("prop-1", "n1")
    before = read(gate.get_audit(args=[a1]))
    assert tx_execution_failed(write(gate.request_audit(args=["prop-1", URL, "n1"])))
    assert read(gate.get_audit(args=[a1])) == before  # no overwrite
    assert tx_execution_succeeded(write(gate.request_audit(args=["prop-1", URL, "n2"])))
    a2 = expected_audit_id("prop-1", "n2")
    assert a1 != a2 and read(gate.has_audit(args=[a2])) is True
