import base64
import hashlib

import pytest

from pkce.flow import (
    begin_auth,
    challenge_for,
    finish_auth,
    flow_batch,
    make_verifier,
    reject_downgrade,
    validate_policy,
    verify_challenge,
)

ENTROPY_A = bytes(range(32))
ENTROPY_B = bytes(range(32, 64))
SAFE_POLICY = {
    "allow_plain": False,
    "min_verifier_length": 64,
    "require_state": True,
}
URL_SAFE = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"
)


def _snapshot(batch):
    fields = ("client", "state", "verifier", "method")
    return {
        client: {name: pending[name] for name in fields}
        for client, pending in batch.items()
    }


# 缺陷 1：verifier 只用时间戳派生，可预测。
def test_verifier_uses_supplied_entropy_not_a_timestamp():
    first = make_verifier(ENTROPY_A, 64)
    second = make_verifier(ENTROPY_A, 64)
    different = make_verifier(ENTROPY_B, 64)

    assert first == second
    assert first != different
    assert not first.isdigit()


# 缺陷 2：verifier 长度不校验，短到八位也能通过。
def test_verifier_length_is_enforced_from_43_through_128():
    shortest = make_verifier(ENTROPY_A, 43)
    longest = make_verifier(ENTROPY_A, 128)

    assert len(shortest) == 43
    assert len(longest) == 128
    assert set(shortest) <= URL_SAFE
    assert set(longest) <= URL_SAFE

    for bad_length in (8, 42, 129):
        with pytest.raises(ValueError):
            make_verifier(ENTROPY_A, bad_length)


# 缺陷 3：challenge 只用明文方法计算，安全方法退化成明文。
def test_s256_challenge_is_sha256_not_plaintext():
    verifier = "a" * 43
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")

    challenge = challenge_for(verifier, "S256")

    assert challenge == expected
    assert challenge != verifier


# 缺陷 4：方法参数被忽略，永远按明文计算。
def test_method_selects_the_challenge_algorithm():
    verifier = "b" * 64

    assert challenge_for(verifier, "plain") == verifier
    assert challenge_for(verifier, "S256") != verifier
    with pytest.raises(ValueError):
        challenge_for(verifier, "sha256")


# 缺陷 5：校验挑战时不比较方法，跨方法也能通过。
def test_verify_challenge_binds_method_with_zero_tolerance():
    verifier = "c" * 64
    s256 = challenge_for(verifier, "S256")

    assert verify_challenge(verifier, s256, "S256") is True
    assert verify_challenge(verifier, verifier, "plain") is True
    assert verify_challenge(verifier, verifier, "S256") is False
    assert verify_challenge(verifier, s256, "plain") is False
    assert verify_challenge(verifier, s256 + "A", "S256") is False
    with pytest.raises(ValueError):
        verify_challenge(verifier, s256, "sha256")


# 缺陷 6：完成授权不校验状态参数，跨会话注入。
def test_finish_auth_rejects_cross_session_state():
    pending_a = begin_auth("client-a", ENTROPY_A)
    pending_b = begin_auth("client-b", ENTROPY_B)

    assert pending_a["method"] == "S256"
    assert pending_a["used"] is False
    assert len(pending_a["state"]) >= 32
    assert pending_a["state"] != pending_b["state"]
    assert pending_a["verifier"] != pending_b["verifier"]

    with pytest.raises(ValueError):
        finish_auth(
            pending_a,
            "code-a",
            pending_b["state"],
            pending_a["verifier"],
        )


# 缺陷 7：状态参数不做过期，旧状态可长期使用。
def test_finish_auth_rejects_expired_state():
    pending = begin_auth("client", ENTROPY_A)
    pending["expires_at"] = 0

    with pytest.raises(ValueError):
        finish_auth(pending, "code", pending["state"], pending["verifier"])


# 缺陷 8：一次性校验缺失，同一 verifier 可重复换取令牌。
def test_finish_auth_rejects_verifier_replay():
    pending = begin_auth("client", ENTROPY_A)

    token = finish_auth(
        pending,
        "code",
        pending["state"],
        pending["verifier"],
    )

    assert set(token) == {"client", "token"}
    assert token["client"] == "client"
    assert isinstance(token["token"], str)
    assert token["token"]
    assert pending["used"] is True

    with pytest.raises(ValueError):
        finish_auth(
            pending,
            "code",
            pending["state"],
            pending["verifier"],
        )


# 缺陷 9：策略校验不检查是否允许明文方法。
def test_policy_flags_all_insecure_settings_in_order():
    issues = validate_policy(
        {
            "allow_plain": True,
            "min_verifier_length": 8,
            "require_state": False,
        }
    )

    assert issues == [
        "plain_allowed",
        "verifier_too_short",
        "state_not_checked",
    ]


# 缺陷 10：批量处理复用待处理状态，后一个流程命中前一个流程的 verifier。
def test_batch_keeps_pending_state_per_flow():
    flows = [
        {"client": "client-a", "entropy": ENTROPY_A},
        {"client": "client-b", "entropy": ENTROPY_B},
    ]

    batch = flow_batch(flows, SAFE_POLICY)

    assert set(batch) == {"client-a", "client-b"}
    assert batch["client-a"] is not batch["client-b"]
    assert batch["client-a"]["verifier"] != batch["client-b"]["verifier"]
    assert batch["client-a"]["state"] != batch["client-b"]["state"]

    with pytest.raises(ValueError):
        finish_auth(
            batch["client-a"],
            "code-a",
            batch["client-b"]["state"],
            batch["client-a"]["verifier"],
        )


def test_challenge_is_stable_for_the_same_verifier():
    verifier = "d" * 64

    assert challenge_for(verifier, "S256") == challenge_for(verifier, "S256")
    assert challenge_for(verifier, "plain") == verifier


def test_wrong_challenge_is_rejected():
    verifier = "e" * 64
    challenge = challenge_for(verifier, "S256")

    assert verify_challenge(verifier, "not-" + challenge, "S256") is False
    assert verify_challenge(verifier + "x", challenge, "S256") is False


def test_plain_method_is_rejected_by_safe_policy():
    plain_flow = [
        {"client": "plain-client", "entropy": ENTROPY_A, "method": "plain"}
    ]

    with pytest.raises(ValueError):
        flow_batch(plain_flow, SAFE_POLICY)

    assert reject_downgrade("plain", ["S256"]) is True
    assert reject_downgrade("S256", ["S256"]) is False
    assert reject_downgrade("plain", ["S256", "plain"]) is False


def test_state_mismatch_is_rejected():
    pending = begin_auth("client", ENTROPY_A)

    with pytest.raises(ValueError):
        finish_auth(
            pending,
            "code",
            "wrong-" + pending["state"],
            pending["verifier"],
        )


def test_two_batches_match_individual_processing():
    flows = [
        {"client": "client-a", "entropy": ENTROPY_A},
        {"client": "client-b", "entropy": ENTROPY_B},
    ]

    first = flow_batch(flows, SAFE_POLICY)
    second = flow_batch(flows, SAFE_POLICY)
    individual = {
        flow["client"]: begin_auth(flow["client"], flow["entropy"])
        for flow in flows
    }
    expected = _snapshot(individual)

    assert _snapshot(first) == expected
    assert _snapshot(second) == expected
    assert first["client-a"] is not second["client-a"]

    first["client-a"]["used"] = True
    assert second["client-a"]["used"] is False
