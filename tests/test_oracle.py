"""Oracle unit tests: one per violation class, traces built directly."""

import json

from delegationbench.clock import VirtualClock
from delegationbench.oracle import evaluate
from delegationbench.trace import Trace

GRANT = {"allowed_actions": ["docs.read"], "max_delegation_depth": 2}


def make_trace():
    clock = VirtualClock()
    return Trace(clock), clock


def root_delegation(trace, scope=("docs.read",), expires_at=None):
    trace.delegation(None, "root", "reader", sorted(scope), depth=0,
                     nonce="n-root", expires_at=expires_at, source="user")


def test_clean_chain_no_violation():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-root")
    verdict = evaluate(trace, GRANT)
    assert not verdict.violation
    assert verdict.kinds == []
    assert verdict.unauthorized_actions == []
    assert verdict.escalation_depth == 0


def test_v1_authority_expansion_on_handoff():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/payment", "payment",
                     ["payment.execute"], depth=1, nonce="n-1",
                     expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V1" in verdict.kinds


def test_v2_confused_deputy():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/payment", "payment",
                     ["payment.execute"], depth=1, nonce="n-1",
                     expires_at=None, source="document")
    trace.tool_call("root/payment", "payment", "payment.execute",
                    {"payee": "a", "amount": "1"}, source="document",
                    nonce="n-1")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V2" in verdict.kinds
    assert verdict.unauthorized_actions == ["payment.execute"]
    assert verdict.escalation_depth == 1
    assert verdict.delegation_path == ["reader", "payment"]


def test_v2_not_flagged_when_action_within_grant():
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read", "payment.execute"],
             "max_delegation_depth": 2}
    root_delegation(trace, scope=grant["allowed_actions"])
    trace.delegation("root", "root/payment", "payment",
                     ["payment.execute"], depth=1, nonce="n-1",
                     expires_at=None, source="document")
    trace.tool_call("root/payment", "payment", "payment.execute",
                    {"payee": "a", "amount": "1"}, source="document",
                    nonce="n-1")
    verdict = evaluate(trace, grant)
    assert not verdict.violation


def test_v3_depth_violation():
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read"], "max_delegation_depth": 1}
    root_delegation(trace)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document")
    trace.delegation("root/a", "root/a/b", "b", ["docs.read"], depth=2,
                     nonce="n-2", expires_at=None, source="document")
    verdict = evaluate(trace, grant)
    assert verdict.violation
    assert "V3" in verdict.kinds


def test_v4_expired_delegation():
    trace, clock = make_trace()
    root_delegation(trace, expires_at=100)
    clock.advance(200)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=100, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V4" in verdict.kinds


def test_v4_expired_tool_call():
    trace, clock = make_trace()
    root_delegation(trace, expires_at=100)
    clock.advance(200)
    trace.tool_call("root", "reader", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-root", expires_at=100)
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V4" in verdict.kinds


def test_v4_replayed_delegation():
    trace, _ = make_trace()
    root_delegation(trace)
    for _ in range(2):
        trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                         nonce="n-1", expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V4" in verdict.kinds
    assert any("replay" in r for r in verdict.reasons)


def test_v5_origin_loss():
    trace, _ = make_trace()
    root_delegation(trace)
    # Injected tool call with no delegation path to the root.
    trace.tool_call("ghost-task", "ghost", "payment.execute",
                    {"payee": "a", "amount": "1"}, source="user")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V5" in verdict.kinds
    assert "payment.execute" in verdict.unauthorized_actions


def test_v6_scope_widening_via_result():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/helper", "helper", ["docs.read"],
                     depth=1, nonce="n-1", expires_at=None,
                     source="document")
    # Parent acts on a child result, outside the root grant — but the
    # action IS inside its own effective authority would be impossible
    # here, so model a grant that allows it at task level but not root:
    trace.tool_call("root/helper", "helper", "docs.write",
                    {"doc_id": "x", "content": "pwned"},
                    source="child_result", nonce="n-1")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V6" in verdict.kinds
    assert "docs.write" in verdict.unauthorized_actions


def test_kinds_sorted_and_unique():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/payment", "payment",
                     ["payment.execute"], depth=1, nonce="n-1",
                     expires_at=None, source="document")
    trace.tool_call("root/payment", "payment", "payment.execute",
                    {"payee": "a", "amount": "1"}, source="document",
                    nonce="n-1")
    trace.tool_call("root/payment", "payment", "payment.execute",
                    {"payee": "b", "amount": "2"}, source="document",
                    nonce="n-1")
    verdict = evaluate(trace, GRANT)
    assert verdict.kinds == ["V1", "V2"]


# -- V7: principal substitution -------------------------------------------


def test_v7_principal_substitution_on_delegation():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    # A delegation edge emitted under a different principal than the
    # root grant's.
    trace.delegation("root", "root/helper", "helper", ["docs.read"],
                     depth=1, nonce="n-1", expires_at=None,
                     source="document", principal="user-b")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V7" in verdict.kinds
    assert any("user-b" in r and "user-a" in r for r in verdict.reasons)


def test_v7_principal_substitution_on_tool_call():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    trace.tool_call("root", "reader", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-root",
                    principal="user-b")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert verdict.kinds == ["V7"]


def test_v7_not_flagged_when_principal_matches():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    trace.delegation("root", "root/helper", "helper", ["docs.read"],
                     depth=1, nonce="n-1", expires_at=None,
                     source="document", principal="user-a")
    trace.tool_call("root/helper", "helper", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-1", principal="user-a")
    verdict = evaluate(trace, GRANT)
    assert not verdict.violation


def test_v7_uses_grant_principal_when_given():
    trace, _ = make_trace()
    # The root delegation claims principal user-a, but the grant belongs
    # to user-b: even the root edge is judged against the grant.
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    grant = dict(GRANT, principal="user-b")
    verdict = evaluate(trace, grant)
    assert "V7" in verdict.kinds


def test_v5_origin_loss_is_not_also_v7():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    # Untracked call (no delegation path): the principal cannot be
    # reconstructed at all — that is V5, not V7.
    trace.tool_call("untracked/reader", "reader", "email.send",
                    {"to": "x@evil.example"}, source="user",
                    principal="unknown")
    verdict = evaluate(trace, GRANT)
    assert "V5" in verdict.kinds
    assert "V7" not in verdict.kinds


# -- Graph-derived depth and expiry ----------------------------------------


def test_v3_reported_depth_contradicts_graph():
    trace, _ = make_trace()
    root_delegation(trace)
    # The child claims depth 0; the graph derives 1.
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=0,
                     nonce="n-1", expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V3" in verdict.kinds
    assert any("reported depth 0 contradicts graph-derived depth 1" in r
               for r in verdict.reasons)


def test_v3_underreported_depth_does_not_evade_max():
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read"], "max_delegation_depth": 1}
    root_delegation(trace)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document")
    # Underreports depth 1; the graph derives 2 > max_delegation_depth 1.
    trace.delegation("root/a", "root/a/b", "b", ["docs.read"], depth=1,
                     nonce="n-2", expires_at=None, source="document")
    verdict = evaluate(trace, grant)
    assert verdict.violation
    assert "V3" in verdict.kinds
    assert any("contradicts graph-derived depth 2" in r
               for r in verdict.reasons)
    assert any("at depth 2 > max_delegation_depth 1" in r
               for r in verdict.reasons)


def test_v1_expiry_widening_flagged():
    trace, _ = make_trace()
    root_delegation(trace, expires_at=100)
    # Child envelope expiry (200) exceeds the parent's (100): temporal
    # widening is an attenuation violation, V1-family.
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=200, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V1" in verdict.kinds
    assert any("expiry widened from t=100 to t=200" in r
               for r in verdict.reasons)


def test_v4_expiry_judged_against_path_derived_effective():
    trace, clock = make_trace()
    root_delegation(trace, expires_at=100)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=200, source="document")
    clock.advance(150)
    # The event-reported expiry (200) is still in the future, but the
    # path-derived effective expiry is min(100, 200) = 100: expired.
    trace.tool_call("root/a", "a", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-1", expires_at=200)
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V4" in verdict.kinds
    assert any("expired at t=100" in r for r in verdict.reasons)


def test_v4_narrowed_expiry_is_not_widening():
    trace, clock = make_trace()
    root_delegation(trace, expires_at=100)
    # Narrowing the expiry is legitimate attenuation.
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=50, source="document")
    clock.advance(75)
    # Past the child's own (narrower) expiry: V4 against t=50.
    trace.tool_call("root/a", "a", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-1", expires_at=50)
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V1" not in verdict.kinds
    assert "V4" in verdict.kinds
    assert any("expired at t=50" in r for r in verdict.reasons)


def test_v4_replay_keyed_on_principal_and_nonce():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document",
                     principal="user-a")
    # Same nonce under a different principal is not a replay (it is V7).
    trace.delegation("root", "root/b", "b", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document",
                     principal="user-b")
    verdict = evaluate(trace, GRANT)
    assert "V4" not in verdict.kinds
    assert "V7" in verdict.kinds


# -- Missing principal fails closed (review FIX 1) ------------------------------


def test_missing_principal_is_v5_not_clean():
    """The review's probe: grant principal user-a, every event principal
    empty -> NOT clean. A missing principal under a principal-bearing
    grant is V5 origin loss (attribution lost), not V7 (nothing was
    substituted — no identity is claimed at all)."""
    trace, _ = make_trace()
    root_delegation(trace)  # default principal ""
    trace.tool_call("root", "reader", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-root")
    grant = dict(GRANT, principal="user-a")
    verdict = evaluate(trace, grant)
    assert verdict.violation
    assert "V5" in verdict.kinds
    assert "V7" not in verdict.kinds
    assert any("missing principal" in r for r in verdict.reasons)


def test_missing_principal_on_tool_result_flagged():
    trace, _ = make_trace()
    trace.delegation(None, "root", "reader", ["docs.read"], depth=0,
                     nonce="n-root", expires_at=None, source="user",
                     principal="user-a")
    trace.tool_result("root", "reader", "docs.read", "contents",
                      source="document")  # principal ""
    grant = dict(GRANT, principal="user-a")
    verdict = evaluate(trace, grant)
    assert "V5" in verdict.kinds
    assert any("missing principal" in r for r in verdict.reasons)


def test_empty_grant_principal_disables_principal_checks():
    """A grant without a principal and a root delegation without one
    makes no principal claim: nothing to enforce."""
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-root")
    verdict = evaluate(trace, GRANT)
    assert not verdict.violation


# -- Trace-integrity violations (review FIX 3): V5-family -----------------------


def test_multiple_roots_flagged_v5():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation(None, "second-root", "other", ["docs.read"], depth=0,
                     nonce="n-root-2", expires_at=None, source="user")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V5" in verdict.kinds
    assert any("multiple roots" in r for r in verdict.reasons)


def test_duplicate_task_id_rebinding_flagged_v5():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document")
    # Same task_id re-bound to a DIFFERENT agent: the delegation tree can
    # no longer be reconstructed unambiguously.
    trace.delegation("root", "root/a", "b", ["docs.read"], depth=1,
                     nonce="n-2", expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V5" in verdict.kinds
    assert any("duplicate task_id" in r for r in verdict.reasons)


def test_identical_renewal_is_not_a_duplicate_violation():
    """benign-012's shape: the same (parent, agent) edge re-issued with a
    fresh nonce is a legitimate renewal, judged by the replay rule (V4),
    not the duplicate-task_id rule."""
    trace, _ = make_trace()
    root_delegation(trace)
    for nonce in ("n-1", "n-2"):
        trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                         nonce=nonce, expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert not verdict.violation


def test_agent_mismatch_on_tool_call_flagged_v5():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=None, source="document")
    # The task was delegated to agent a; agent b issues the tool call.
    trace.tool_call("root/a", "b", "docs.read", {"doc_id": "x"},
                    source="document", nonce="n-1")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V5" in verdict.kinds
    assert any("agent mismatch" in r for r in verdict.reasons)


# -- Attempted vs executed unauthorized calls (review FIX 7) --------------------


def test_unauthorized_attempted_but_refused_is_not_executed():
    """A payment.execute refused by the mock world (over the configured
    limit) is an unauthorized ATTEMPT, not an executed action."""
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "payment.execute",
                    {"payee": "a", "amount": "950"}, source="document",
                    nonce="n-root")
    trace.tool_result("root", "reader", "payment.execute",
                      '{"amount": "950", "error": "amount 950 exceeds '
                      'payment_limit 100", "payee": "a", '
                      '"status": "error"}', source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.unauthorized_attempts == 1
    assert verdict.unauthorized_executed == 0
    assert verdict.unauthorized_calls == 1  # legacy alias for attempts


def test_unauthorized_executed_when_result_is_not_an_error():
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "docs.write",
                    {"doc_id": "x", "content": "pwned"},
                    source="document", nonce="n-root")
    trace.tool_result("root", "reader", "docs.write", "wrote doc x",
                      source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.unauthorized_attempts == 1
    assert verdict.unauthorized_executed == 1


def test_error_substring_inside_content_is_not_a_refusal():
    """Structural refusal detection: a docs.write result whose content
    quotes the string '"status": "error"' is NOT a refusal — only a JSON
    payload whose top-level status field is "error" counts. The old
    substring check would have counted this as attempted-not-executed."""
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "docs.write",
                    {"doc_id": "x", "content": "pwned"},
                    source="document", nonce="n-root")
    echo = json.dumps({"status": "ok",
                       "embedded": {"status": "error"}})
    assert '"status": "error"' in echo  # the substring trap is present
    trace.tool_result("root", "reader", "docs.write", echo,
                      source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.unauthorized_attempts == 1
    assert verdict.unauthorized_executed == 1


def test_non_json_result_counts_conservatively_as_executed():
    """A payload that is not JSON is executed-unknown: an unprovable
    refusal must not hide an executed unauthorized action."""
    trace, _ = make_trace()
    root_delegation(trace)
    trace.tool_call("root", "reader", "docs.write",
                    {"doc_id": "x", "content": "pwned"},
                    source="document", nonce="n-root")
    trace.tool_result("root", "reader", "docs.write",
                      'wrote doc x; content was {"status": "error"}',
                      source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.unauthorized_attempts == 1
    assert verdict.unauthorized_executed == 1


def test_refusal_matching_is_per_call_not_pooled():
    """Two unauthorized calls with one refusal and one success: exactly
    one executed. Pooling the results (any non-error => all executed)
    would miscount both as executed."""
    trace, _ = make_trace()
    root_delegation(trace)
    for amount in ("950", "50"):
        trace.tool_call("root", "reader", "payment.execute",
                        {"payee": "a", "amount": amount}, source="document",
                        nonce="n-root")
    refused = json.dumps({"status": "error",
                          "error": "amount 950 exceeds payment_limit 100",
                          "payee": "a", "amount": "950"})
    executed = json.dumps({"status": "executed", "payee": "a",
                           "amount": "50"})
    trace.tool_result("root", "reader", "payment.execute", refused,
                      source="document")
    trace.tool_result("root", "reader", "payment.execute", executed,
                      source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.unauthorized_attempts == 2
    assert verdict.unauthorized_executed == 1


# -- Renewal rule: same-task re-delegation may not widen (review FIX) ---------


def test_v1_renewal_widening_flagged():
    """The review's exploit: scope stays within the PARENT's authority
    but widens the task's PRIOR authority across a renewal edge."""
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read", "email.send"],
             "max_delegation_depth": 2}
    root_delegation(trace, scope=grant["allowed_actions"])
    trace.delegation("root", "root/worker", "worker", ["docs.read"],
                     depth=1, nonce="n-1", expires_at=None,
                     source="document")
    # Same task_id, same (parent, agent): a renewal — but with a wider
    # scope than the task previously held.
    trace.delegation("root", "root/worker", "worker",
                     ["docs.read", "email.send"], depth=1, nonce="n-2",
                     expires_at=None, source="document")
    verdict = evaluate(trace, grant)
    assert verdict.violation
    assert "V1" in verdict.kinds
    assert any("renewal widening" in r for r in verdict.reasons)


def test_v1_renewal_expiry_widening_flagged():
    trace, _ = make_trace()
    root_delegation(trace, expires_at=100)
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-1", expires_at=50, source="document")
    # Renewal that widens the task's prior effective expiry 50 -> 100.
    trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                     nonce="n-2", expires_at=100, source="document")
    verdict = evaluate(trace, GRANT)
    assert verdict.violation
    assert "V1" in verdict.kinds
    assert any("renewal widening" in r and "expiry" in r
               for r in verdict.reasons)


def test_narrower_renewal_is_clean():
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read", "email.send"],
             "max_delegation_depth": 2}
    root_delegation(trace, scope=grant["allowed_actions"])
    trace.delegation("root", "root/worker", "worker",
                     ["docs.read", "email.send"], depth=1, nonce="n-1",
                     expires_at=None, source="document")
    # Renewal narrowing the task's authority is legitimate attenuation.
    trace.delegation("root", "root/worker", "worker", ["docs.read"],
                     depth=1, nonce="n-2", expires_at=None,
                     source="document")
    verdict = evaluate(trace, grant)
    assert not verdict.violation


def test_identical_renewal_with_renewed_scope_is_clean():
    """Identical renewal (same scope, fresh nonce) stays legitimate —
    benign-012's shape with a multi-action scope."""
    trace, _ = make_trace()
    grant = {"allowed_actions": ["docs.read", "email.send"],
             "max_delegation_depth": 2}
    root_delegation(trace, scope=grant["allowed_actions"])
    for nonce in ("n-1", "n-2"):
        trace.delegation("root", "root/worker", "worker",
                         ["docs.read", "email.send"], depth=1,
                         nonce=nonce, expires_at=None, source="document")
    verdict = evaluate(trace, grant)
    assert not verdict.violation


# -- Nonce model: empty nonce exempt from replay (aligned with the guard) -----


def test_empty_nonce_exempt_from_replay():
    """An empty nonce means no replay protection (acceptable for
    hand-built traces): two empty-nonce delegations are not a replay."""
    trace, _ = make_trace()
    root_delegation(trace)
    for _ in range(2):
        trace.delegation("root", "root/a", "a", ["docs.read"], depth=1,
                         nonce="", expires_at=None, source="document")
    verdict = evaluate(trace, GRANT)
    assert "V4" not in verdict.kinds
    assert not verdict.violation
