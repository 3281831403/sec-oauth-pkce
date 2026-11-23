"""PKCE authorization-flow contracts.

The implementations below close the ten intercepted-authorization-code
replay defects.  Each section is annotated with the defect number it fixes.

Randomness is supplied explicitly through the entropy arguments.  No function
may read a clock, a global random source, or process state to create a
verifier or an authorization state.  The clock is read only to stamp
issued_at / expires_at, and the OS random source is used only to mint the
final opaque access token.
"""

import base64
import hashlib
import hmac
import secrets
import time

S256 = "S256"
PLAIN = "plain"
_KNOWN_METHODS = (S256, PLAIN)

_MIN_VERIFIER_LENGTH = 43
_MAX_VERIFIER_LENGTH = 128
_STATE_TTL_SECONDS = 300
_POLICY_MIN_VERIFIER_LENGTH = 43


def _method_or_raise(method: str) -> None:
    if method not in _KNOWN_METHODS:
        raise ValueError(f"unknown PKCE method: {method!r}")


def make_verifier(entropy: bytes, length: int) -> str:
    """Create a high-entropy PKCE verifier using only the supplied entropy.

    Contract:
    - entropy is a bytes object with at least 32 bytes.  A shorter value must
      raise ValueError.
    - length is inclusive in the range 43 through 128.  Any other length must
      raise ValueError.
    - The result is exactly length characters long and contains only the
      URL-safe characters A-Z, a-z, 0-9, hyphen, dot, and underscore.
    - The result is deterministic for the same entropy and length, but a
      different entropy must produce a different verifier.  It must not be
      derived from a timestamp or from a hidden random source.
    """
    # 缺陷 1：verifier 只用时间戳派生，可预测。
    # 只接受调用方提供的高熵字节，并通过 SHA-256 计数器模式扩展成密钥流，
    # 完全不接触时钟或全局随机源，因此结果可复现且不可预测。
    if not isinstance(entropy, bytes) or len(entropy) < 32:
        raise ValueError("entropy must be a bytes object of at least 32 bytes")

    # 缺陷 2：verifier 长度不校验，短到八位也能通过。
    # RFC 7636 要求 verifier 长度落在 43..128，越界一律拒绝。
    if not isinstance(length, int) or not (
        _MIN_VERIFIER_LENGTH <= length <= _MAX_VERIFIER_LENGTH
    ):
        raise ValueError(
            "length must be an integer in the inclusive range 43 through 128"
        )

    chunks = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < length:
        block = hashlib.sha256(
            b"pkce-verifier:" + entropy + counter.to_bytes(8, "big")
        ).digest()
        chunks.append(
            base64.urlsafe_b64encode(block).rstrip(b"=").decode("ascii")
        )
        counter += 1
    return "".join(chunks)[:length]


def challenge_for(verifier: str, method: str) -> str:
    """Derive the PKCE challenge for a verifier and an explicit method.

    Contract:
    - method is exactly S256 or plain.  Any other value raises ValueError.
    - For S256, return the unpadded URL-safe base64 encoding of the SHA-256
      digest of the ASCII verifier.
    - For plain, return the verifier unchanged.
    - The method argument must be honored.  An S256 request must never silently
      fall back to the plain method.
    """
    _method_or_raise(method)

    if method == S256:
        # 缺陷 3：challenge 只用明文方法计算，安全方法退化成明文。
        # S256 必须真正做 SHA-256 摘要，输出与 verifier 明文不同。
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    # 缺陷 4：方法参数被忽略，永远按明文计算。
    # 只有显式请求 plain 时才原样返回；未知方法已在入口处拒绝。
    return verifier


def begin_auth(client: str, entropy: bytes) -> dict:
    """Start an authorization flow and return a fresh pending mapping.

    Contract:
    - client is a non-empty client identifier and entropy is passed to
      make_verifier.
    - The returned mapping has exactly these required keys:
      client, state, verifier, method, issued_at, expires_at, used.
    - verifier is make_verifier(entropy, 64).
    - state is a URL-safe, high-entropy string of at least 32 characters,
      derived only from entropy and distinct from the verifier.
    - method is S256, used is False, issued_at is the current Unix time, and
      expires_at is issued_at plus 300 seconds.
    - Every call returns an independent pending mapping.  No pending state may
      be cached or shared between calls.
    """
    if not isinstance(client, str) or not client:
        raise ValueError("client must be a non-empty client identifier")

    # verifier 与 state 做域分离：即便同源 entropy，两者也必然不同，
    # 且整条推导链只依赖传入的 entropy（配合缺陷 1/6/10 的修复）。
    verifier = make_verifier(entropy, 64)
    state_entropy = hashlib.sha256(b"pkce-state:" + entropy).digest()
    state = make_verifier(state_entropy, _MIN_VERIFIER_LENGTH)

    issued_at = time.time()
    return {
        "client": client,
        "state": state,
        "verifier": verifier,
        "method": S256,
        "issued_at": issued_at,
        "expires_at": issued_at + _STATE_TTL_SECONDS,
        "used": False,
    }


def verify_challenge(verifier: str, challenge: str, method: str) -> bool:
    """Check a verifier against a challenge with zero tolerance.

    Contract:
    - method must be S256 or plain; an unknown method raises ValueError.
    - The expected challenge is computed with challenge_for using the supplied
      method, so a challenge produced for a different method must be rejected.
    - Comparison uses hmac.compare_digest and is exact: no prefix matching, no
      case folding, no padding tolerance, and no fallback to another method.
    - Return True only for an exact match and False for any mismatch.
    """
    _method_or_raise(method)

    # 缺陷 5：校验挑战时不比较方法，跨方法也能通过。
    # 期望值严格用调用方声明的方法计算，S256 的挑战绝不会拿去和 plain 比对；
    # compare_digest 保证常量时间、逐字符精确匹配，无任何回退路径。
    expected = challenge_for(verifier, method)
    return hmac.compare_digest(expected, challenge)


def finish_auth(
    pending: dict, code: str, state: str, verifier: str
) -> dict:
    """Complete an authorization flow exactly once.

    Contract:
    - pending is a mapping returned by begin_auth and code is a non-empty
      authorization code.
    - Reject with ValueError when any of these checks fails:
      pending was already used; the state is expired, meaning the current Unix
      time is at or beyond expires_at; state does not match pending state;
      verifier does not match pending verifier and method; code is empty.
    - State comparison must use hmac.compare_digest and have zero tolerance.
    - On success set pending used to True and return a mapping with exactly the
      keys client and token.  token is a non-empty opaque string.  A rejected
      call must not mark the pending flow as used.
    - A second call with the same pending flow, state, and verifier must fail,
      even when the same authorization code is presented.
    """
    # 缺陷 8：一次性校验缺失，同一 verifier 可重复换取令牌。
    # 入口先查 used，已消费的待处理流程直接拒绝，且任何拒绝路径都在
    # 写入 used 之前返回，保证失败不会污染一次性标记。
    if pending["used"]:
        raise ValueError("authorization flow has already been used")

    # 缺陷 7：状态参数不做过期，旧状态可长期使用。
    # 当前时间到达或超过 expires_at 即视为过期，拒绝重放旧状态。
    if time.time() >= pending["expires_at"]:
        raise ValueError("authorization state has expired")

    # 缺陷 6：完成授权不校验状态参数，跨会话注入。
    # state 必须与本待处理流程绑定的值常量时间精确匹配，
    # 拿着另一个会话的 state 无法驱动本流程完成。
    if not hmac.compare_digest(state, pending["state"]):
        raise ValueError("state does not match the pending authorization")

    # verifier 必须通过待处理流程登记的方法校验，方法绑定不可绕过。
    expected_challenge = challenge_for(pending["verifier"], pending["method"])
    if not verify_challenge(verifier, expected_challenge, pending["method"]):
        raise ValueError("verifier does not match the pending challenge")

    if not code:
        raise ValueError("authorization code must be non-empty")

    # 全部检查通过后才允许置位并签发令牌。
    pending["used"] = True
    return {
        "client": pending["client"],
        "token": secrets.token_urlsafe(32),
    }


def reject_downgrade(method: str, allowed: list[str]) -> bool:
    """Report whether a requested method must be rejected as a downgrade.

    Contract:
    - Return True when method is plain and plain is not present in allowed.
    - Return True for an unknown method, because it is not explicitly allowed.
    - Return False when method is present in allowed.
    - The function is a pure predicate and must not mutate allowed.
    """
    # 缺陷 9（策略侧）：白名单之外的方法一律视为降级，plain 未被显式
    # 允许时同样拒绝；纯谓词，不修改 allowed。
    return method not in allowed


def validate_policy(policy: dict) -> list[str]:
    """Return the security issues in a policy in a fixed order.

    Contract:
    - policy is a mapping with allow_plain, min_verifier_length, and
      require_state keys.
    - Return a list of issue codes in this exact order:
      plain_allowed when allow_plain is true;
      verifier_too_short when min_verifier_length is less than 43;
      state_not_checked when require_state is not true.
    - Return an empty list for a policy with no issues.  Do not raise for the
      insecure values themselves; report them as issue codes.
    """
    issues = []

    # 缺陷 9：策略校验不检查是否允许明文方法。
    # 允许 plain 必须显式上报 plain_allowed，配合 reject_downgrade 在
    # 批量处理中真正拦截明文方法。
    if policy["allow_plain"]:
        issues.append("plain_allowed")
    if policy["min_verifier_length"] < _POLICY_MIN_VERIFIER_LENGTH:
        issues.append("verifier_too_short")
    if policy["require_state"] is not True:
        issues.append("state_not_checked")

    return issues


def flow_batch(flows: list[dict], policy: dict) -> dict:
    """Process authorization flows independently and key results by client.

    Contract:
    - Each flow mapping has client and entropy keys and an optional method key
      that defaults to S256.  policy uses the validate_policy contract.
    - Validate policy first; any reported issue raises ValueError.
    - Reject each flow whose method is disallowed by policy, in particular a
      plain flow when allow_plain is false.  Reject unknown methods and
      duplicate client identifiers with ValueError.
    - Call begin_auth with each flow's own client and entropy.  Never reuse a
      pending mapping, verifier, or state from another flow or from an earlier
      batch.  Set the returned pending method to the flow's requested method.
    - Return a dict mapping every client identifier to that flow's pending
      mapping.  Two batches over equal flows must produce equal security
      fields, and each batch must use fresh independent pending mappings.
    """
    issues = validate_policy(policy)
    if issues:
        raise ValueError(f"insecure policy: {', '.join(issues)}")

    allowed_methods = [S256]
    if policy["allow_plain"]:
        allowed_methods.append(PLAIN)

    batch = {}
    for flow in flows:
        client = flow["client"]
        if client in batch:
            raise ValueError(f"duplicate client identifier: {client!r}")

        method = flow.get("method", S256)
        if reject_downgrade(method, allowed_methods):
            raise ValueError(
                f"method {method!r} is disallowed by the active policy"
            )

        # 缺陷 10：批量处理复用待处理状态，后一个流程命中前一个流程的
        # verifier。每个 flow 都用自己的 client/entropy 调 begin_auth 取得
        # 独立 pending，再覆盖为本 flow 请求的方法，绝不复用前一个流程的
        # 任何状态；下一批次同样重新生成全新映射。
        pending = begin_auth(client, flow["entropy"])
        pending["method"] = method
        batch[client] = pending

    return batch
