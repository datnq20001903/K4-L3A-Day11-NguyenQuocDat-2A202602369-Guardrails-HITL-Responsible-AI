import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from assignment.pipeline import (
    build_observability,
    build_production_plugins,
    is_egress_allowed,
)
import assignment.pipeline as pipeline
from assignment import rate_limiter
from assignment.rate_limiter import RateLimitPlugin


def test_rate_limit_is_per_user_and_expires_old_requests(monkeypatch):
    plugin = RateLimitPlugin(max_requests=2, window_seconds=60)
    clock = iter([100.0, 101.0, 102.0, 161.0])
    monkeypatch.setattr(rate_limiter.time, "time", lambda: next(clock))

    async def exercise():
        alice = SimpleNamespace(user_id="alice")
        bob = SimpleNamespace(user_id="bob")
        message = None
        assert await plugin.on_user_message_callback(
            invocation_context=alice, user_message=None
        ) is None
        assert await plugin.on_user_message_callback(
            invocation_context=alice, user_message=None
        ) is None
        message = await plugin.on_user_message_callback(
            invocation_context=alice, user_message=None
        )
        bob_result = await plugin.on_user_message_callback(
            invocation_context=bob, user_message=None
        )
        return message, bob_result

    blocked, bob_allowed = asyncio.run(exercise())

    assert blocked is not None
    assert "rate limit" in blocked.parts[0].text.lower()
    assert bob_allowed is None
    assert plugin.blocked_count == 1


def test_rate_limit_allows_request_after_window_expires(monkeypatch):
    plugin = RateLimitPlugin(max_requests=1, window_seconds=60)
    clock = iter([100.0, 161.0])
    monkeypatch.setattr(rate_limiter.time, "time", lambda: next(clock))
    context = SimpleNamespace(user_id="alice")

    async def exercise():
        first = await plugin.on_user_message_callback(
            invocation_context=context, user_message=None
        )
        second = await plugin.on_user_message_callback(
            invocation_context=context, user_message=None
        )
        return first, second

    first, second = asyncio.run(exercise())

    assert first is None
    assert second is None
    assert plugin.blocked_count == 0


def test_audit_log_records_input_output_latency_and_exports_json():
    audit = AuditLogPlugin()

    audit.record_input(user_id="alice", text="What is my balance?", request_id="r1")
    audit.record_output(
        user_id="alice",
        text="Your balance is protected.",
        blocked=False,
        layer=None,
        request_id="r1",
    )
    path = Path(".test-audit-output.json")
    try:
        audit.export_json(str(path))
        exported = json.loads(path.read_text(encoding="utf-8"))
        assert len(exported) == 2
        assert exported[0]["event"] == "input"
        assert exported[1]["event"] == "output"
        assert exported[1]["latency_ms"] >= 0
        assert exported[1]["blocked"] is False
    finally:
        path.unlink(missing_ok=True)


def test_monitoring_alerts_and_exports_threshold_breaches():
    monitoring = MonitoringAlert(
        block_rate_threshold=0.5,
        rate_limit_hit_threshold=2,
        judge_fail_rate_threshold=0.3,
    )
    monitoring.total_requests = 4
    monitoring.blocked_requests = 3
    monitoring.rate_limit_hits = 3
    monitoring.judge_checks = 4
    monitoring.judge_fails = 2

    alerts = monitoring.check_metrics()
    path = Path(".test-metrics-output.json")
    try:
        monitoring.export_json(str(path))
        exported = json.loads(path.read_text(encoding="utf-8"))
        assert {alert.metric for alert in alerts} == {
            "block_rate",
            "rate_limit_hits",
            "judge_fail_rate",
        }
        assert exported["total_requests"] == 4
        assert len(exported["alerts"]) == 3
    finally:
        path.unlink(missing_ok=True)


def test_egress_requires_exact_vinbank_https_endpoint_and_safe_payload():
    assert is_egress_allowed(
        "https://api.vinbank.example/v1/transfers", "approved transfer amount 500000"
    ) is True
    assert is_egress_allowed(
        "http://api.vinbank.example/v1/transfers", "approved transfer amount 500000"
    ) is False
    assert is_egress_allowed(
        "https://api.vinbank.example.evil.com/v1/transfers", "approved transfer amount 500000"
    ) is False
    assert is_egress_allowed(
        "https://api.vinbank.example/v1/transfers", "admin password is admin123"
    ) is False
    assert is_egress_allowed(
        "https://api.vinbank.example/v1/transfers", "email test@vinbank.com"
    ) is False


def test_production_plugins_and_observability_have_required_order():
    plugins = build_production_plugins(max_requests=3, window_seconds=10)
    audit, monitoring = build_observability()

    assert [plugin.name for plugin in plugins] == [
        "rate_limiter",
        "input_guardrail",
        "output_guardrail",
    ]
    assert isinstance(audit, AuditLogPlugin)
    assert isinstance(monitoring, MonitoringAlert)


def test_assignment_suite_generates_required_result_groups(monkeypatch):
    async def fake_chat(agent, runner, text):
        return f"Safe banking response for: {text}", None

    monkeypatch.setattr(
        pipeline,
        "create_blue_agent",
        lambda plugins: (SimpleNamespace(), SimpleNamespace()),
        raising=False,
    )
    monkeypatch.setattr(pipeline, "chat_with_agent", fake_chat, raising=False)

    async def exercise():
        return await pipeline.run_assignment_suite(
            {
                "plugins": build_production_plugins(),
                "audit": AuditLogPlugin(),
                "monitor": MonitoringAlert(),
            }
        )

    generated = [
        Path("outputs/results.json"),
        Path("outputs/audit_log.json"),
        Path("outputs/metrics.json"),
    ]
    try:
        result = asyncio.run(exercise())
        assert result["framework"] == "google-adk"
        assert len(result["safe_queries"]) >= 5
        assert len(result["attack_queries"]) >= 7
        assert len(result["edge_cases"]) >= 3
        assert result["rate_limit"]["passed"] + result["rate_limit"]["blocked"] == result["rate_limit"]["sent"]
        assert all(path.exists() for path in generated)
    finally:
        for path in generated:
            path.unlink(missing_ok=True)
        try:
            Path("outputs").rmdir()
        except OSError:
            pass
