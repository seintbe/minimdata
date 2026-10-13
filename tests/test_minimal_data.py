"""最小数据参考实现的验收测试。

每个测试对应设计文档 §7 验收表的一行。
运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from minimal_data import (  # noqa: E402
    DataScope,
    FirstReadGate,
    ReadRequest,
    ResourceIdentity,
    glob_match,
    infer_sensitivity,
    normalize_resource_id,
    resolve_path,
)


def load_scope() -> DataScope:
    raw = json.loads(
        (ROOT / "examples" / "data-scope.summarize-paper.json").read_text("utf-8")
    )
    return DataScope.from_dict(raw)


class TestUnlistedResourceDenied(unittest.TestCase):
    """验收：未声明资源被拒 → DENY。"""

    def test_ssh_key_denied(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/home/user/.ssh/id_rsa", version_id="inode:99:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=1024))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "resource_not_declared")

    def test_env_file_denied(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/etc/shadow", version_id="inode:12:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=512))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertIsNone(event["decision"]["matchedInputId"])


class TestSymlinkDoesNotBypassPrefix(unittest.TestCase):
    """验收：软链不绕过前缀匹配 —— 匹配在解析后路径上执行。"""

    def test_symlink_pointing_outside_scope_is_denied(self):
        gate = FirstReadGate(load_scope())
        # 原始路径看起来在 /papers 下，实际解析到 /etc/shadow
        ident = resolve_path(
            "/papers/current/readme.md",
            link_target="/etc/shadow",
            version_id="inode:12:1",
        )
        self.assertEqual(ident.resolved_path, "/etc/shadow")
        event = gate.request_read(ident, ReadRequest(requested_bytes=100))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "resource_not_declared")

    def test_link_chain_recorded(self):
        ident = resolve_path(
            "/papers/current/readme.md",
            link_target="/etc/shadow",
            version_id="inode:12:1",
        )
        self.assertEqual(ident.link_chain, ("/papers/current/readme.md", "/etc/shadow"))

    def test_symlink_inside_scope_allowed(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path(
            "/papers/current/paper-a.pdf",
            link_target="/papers/paper-a.pdf",
            version_id="inode:77:1",
        )
        event = gate.request_read(ident, ReadRequest(requested_bytes=1000))
        self.assertEqual(event["decision"]["verdict"], "ALLOW")


class TestNonRecursiveGlob(unittest.TestCase):
    """验收：非递归 glob 不下钻。"""

    def test_star_does_not_cross_slash(self):
        self.assertTrue(glob_match("/papers/*", "/papers/paper-a.pdf"))
        self.assertFalse(glob_match("/papers/*", "/papers/2026/paper-a.pdf"))

    def test_recursive_glob_crosses_slash(self):
        self.assertTrue(
            glob_match("/papers/**", "/papers/2026/paper-a.pdf", recursive=True)
        )

    def test_glob_no_descent_denied_when_unlisted(self):
        gate = FirstReadGate(load_scope())
        # /papers/2026/paper-b.pdf 既不被 /papers/* 覆盖，也不在声明清单中
        ident = resolve_path("/papers/2026/paper-b.pdf", version_id="inode:5:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=100))
        self.assertEqual(event["decision"]["verdict"], "DENY")

    def test_crosses_directory_helper(self):
        from minimal_data import crosses_directory

        self.assertTrue(crosses_directory("/papers/2026/x.pdf", "/papers/*"))
        self.assertFalse(crosses_directory("/papers/x.pdf", "/papers/*"))


class TestSensitivityCeiling(unittest.TestCase):
    """验收：超天花板敏感度被拒。"""

    def test_secret_exceeding_internal_ceiling_denied(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path(
            "/papers/paper-a.pdf",
            version_id="inode:77:1",
            content_probe="-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        )
        event = gate.request_read(ident, ReadRequest(requested_bytes=1000))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "sensitivity_ceiling_exceeded")
        self.assertEqual(event["sensitivity"]["level"], "secret")

    def test_internal_within_internal_ceiling_allowed(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=1000))
        self.assertEqual(event["decision"]["verdict"], "ALLOW")
        self.assertEqual(event["sensitivity"]["level"], "internal")

    def test_public_template_rejects_internal_content(self):
        """模板天花板是 public，命中 confidential 内容应被拒。"""
        gate = FirstReadGate(load_scope())
        ident = resolve_path(
            "/templates/mail/welcome.md",
            version_id="inode:31:1",
            content_probe="api_key = 'abcdef'",
        )
        event = gate.request_read(ident, ReadRequest(requested_bytes=100))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "sensitivity_ceiling_exceeded")


class TestSensitivityUnknownNeverAllowed(unittest.TestCase):
    """验收：敏感度未知不默认放行 → REVIEW 或 DENY，绝不 ALLOW。"""

    def test_unknown_sensitivity_review(self):
        scope = load_scope()
        # 清空规则表与目录先验可命中的情形：使用一个无规则覆盖的已声明路径
        scope.sensitivity_rules = []
        scope.declared_inputs[0].resource = normalize_resource_id("file:/tmp/x.dat")
        scope.declared_inputs[0].sensitivity_ceiling = "internal"
        gate = FirstReadGate(scope)
        ident = resolve_path("/tmp/x.dat", version_id="inode:1:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=10))
        self.assertEqual(event["sensitivity"]["level"], "UNKNOWN")
        self.assertEqual(event["decision"]["verdict"], "REVIEW")
        self.assertNotEqual(event["decision"]["verdict"], "ALLOW")

    def test_unknown_sensitivity_strict_mode_denies(self):
        scope = load_scope()
        scope.sensitivity_rules = []
        scope.strict_mode = True
        scope.declared_inputs[0].resource = normalize_resource_id("file:/tmp/x.dat")
        gate = FirstReadGate(scope)
        ident = resolve_path("/tmp/x.dat", version_id="inode:1:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=10))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "sensitivity_unknown")

    def test_absent_probe_is_not_public(self):
        """S3 未命中不等于 public：这是 3.2 的核心约束。"""
        ident = ResourceIdentity(
            resource_id="file:/tmp/ambiguous.bin",
            resolved_path="/tmp/ambiguous.bin",
            origin_path="/tmp/ambiguous.bin",
            version_id="inode:2:1",
        )
        verdict = infer_sensitivity(ident, DataScope(task_id="t"))
        self.assertEqual(verdict.level, "UNKNOWN")
        self.assertEqual(verdict.source, "none")


class TestCollectorGap(unittest.TestCase):
    """验收：采集缺口降级 → UNKNOWN，不进入放行分支。"""

    def test_gap_yields_unknown_not_allow(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        event = gate.request_read(
            ident,
            ReadRequest(requested_bytes=1000, coverage_gaps=["frida_not_attached"]),
        )
        self.assertEqual(event["decision"]["verdict"], "UNKNOWN")
        self.assertEqual(event["decision"]["reason"], "collector_gap")
        self.assertEqual(event["coverageGaps"], ["frida_not_attached"])

    def test_gap_granted_bytes_not_registered(self):
        """UNKNOWN 不登记授予范围，后续重读仍需重新判定。"""
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        gate.request_read(
            ident,
            ReadRequest(requested_bytes=1000, coverage_gaps=["x"]),
        )
        self.assertEqual(gate.granted_resources(), set())


class TestByteBudgetTruncation(unittest.TestCase):
    """验收：超预算被截断而非读后丢弃 → grantedBytes == maxBytes。"""

    def test_truncate_at_max_bytes(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=999999))
        self.assertEqual(event["decision"]["verdict"], "TRUNCATE")
        self.assertEqual(event["read"]["grantedBytes"], 131072)
        self.assertEqual(event["read"]["requestedBytes"], 999999)
        self.assertTrue(event["read"]["truncated"])

    def test_within_budget_allowed(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        event = gate.request_read(ident, ReadRequest(requested_bytes=1000))
        self.assertEqual(event["decision"]["verdict"], "ALLOW")
        self.assertFalse(event["read"]["truncated"])


class TestReadFolding(unittest.TestCase):
    """验收：同版本重读不新增事件；版本变化则新增。"""

    def test_same_version_repeat_does_not_add_event(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        first = gate.request_read(ident, ReadRequest(requested_bytes=1000))
        self.assertFalse(first["folded"])
        self.assertEqual(gate.input_surface(), 1)

        second = gate.request_read(ident, ReadRequest(requested_bytes=800))
        self.assertTrue(second["folded"])
        self.assertEqual(second["decision"]["reason"], "repeat_read_within_granted_range")
        self.assertEqual(gate.input_surface(), 1)

    def test_scope_extension_rejudged(self):
        gate = FirstReadGate(load_scope())
        ident = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        gate.request_read(ident, ReadRequest(requested_bytes=1000))
        extended = gate.request_read(ident, ReadRequest(requested_bytes=5000))
        self.assertFalse(extended["folded"])
        self.assertTrue(extended["decision"]["reason"].startswith("scope_extension:"))
        self.assertEqual(gate.input_surface(), 2)

    def test_version_change_produces_new_event(self):
        """TOCTOU 防护：内容变化使先前判定失效。"""
        gate = FirstReadGate(load_scope())
        v1 = resolve_path("/papers/paper-a.pdf", version_id="inode:77:1")
        gate.request_read(v1, ReadRequest(requested_bytes=1000))
        v2 = resolve_path("/papers/paper-a.pdf", version_id="inode:77:2")
        event = gate.request_read(v2, ReadRequest(requested_bytes=1000))
        self.assertFalse(event["folded"])
        self.assertEqual(gate.input_surface(), 2)


class TestInputSurfaceCountable(unittest.TestCase):
    """验收：信息面可计数 → InputSurface(T) 等于首读事件数。"""

    def test_surface_equals_event_count(self):
        gate = FirstReadGate(load_scope())
        gate.request_read(
            resolve_path("/papers/paper-a.pdf", version_id="inode:77:1"),
            ReadRequest(requested_bytes=1000),
        )
        gate.request_read(
            resolve_path("/templates/mail/welcome.md", version_id="inode:31:1"),
            ReadRequest(requested_bytes=500),
        )
        gate.request_read(
            resolve_path("/home/user/.ssh/id_rsa", version_id="inode:99:1"),
            ReadRequest(requested_bytes=1000),
        )
        self.assertEqual(gate.input_surface(), 3)
        self.assertEqual(len(gate.events), 3)

    def test_audit_report_ratio(self):
        gate = FirstReadGate(load_scope())
        gate.request_read(
            resolve_path("/papers/paper-a.pdf", version_id="inode:77:1"),
            ReadRequest(requested_bytes=1000),
        )
        gate.request_read(
            resolve_path("/home/user/.ssh/id_rsa", version_id="inode:99:1"),
            ReadRequest(requested_bytes=1000),
        )
        report = gate.audit_report(declared_count=3)
        self.assertEqual(report["inputSurface"], 2)
        self.assertEqual(report["declaredInputs"], 3)
        self.assertEqual(report["verdicts"]["DENY"], 1)
        self.assertEqual(report["verdicts"]["ALLOW"], 1)


class TestRequiredInputUnavailable(unittest.TestCase):
    """required 输入不可用时应提前失败，而非静默降级。"""

    def test_required_missing_version_denied(self):
        gate = FirstReadGate(load_scope())
        ident = ResourceIdentity(
            resource_id="file:/papers/paper-a.pdf",
            resolved_path="/papers/paper-a.pdf",
            origin_path="/papers/paper-a.pdf",
            version_id=None,
        )
        event = gate.request_read(ident, ReadRequest(requested_bytes=100))
        self.assertEqual(event["decision"]["verdict"], "DENY")
        self.assertEqual(event["decision"]["reason"], "required_input_unavailable")


class TestSensitivityPrecedence(unittest.TestCase):
    """取所有来源中最高敏感级别；来源分级只记录由谁证明。"""

    def test_policy_floor_beats_owner_self_declaration(self):
        """S1 标注 public 不能降低 S2 策略要求的 internal。

        资源所有者的自我声明不是放松 Agent 自身策略的依据，因此策略构成下界。
        """
        scope = load_scope()
        ident = resolve_path(
            "/papers/paper-a.pdf",
            version_id="inode:77:1",
            explicit_sensitivity="public",
        )
        verdict = infer_sensitivity(ident, scope)
        self.assertEqual(verdict.level, "internal")
        self.assertEqual(verdict.source, "S2_policy")

    def test_owner_declaration_raises_above_policy(self):
        """S1 标注 secret 高于 S2 策略的 internal，取 secret。"""
        scope = load_scope()
        ident = resolve_path(
            "/papers/paper-a.pdf",
            version_id="inode:77:1",
            explicit_sensitivity="secret",
        )
        verdict = infer_sensitivity(ident, scope)
        self.assertEqual(verdict.level, "secret")
        self.assertEqual(verdict.source, "S1_explicit")
        self.assertEqual(verdict.confidence, "CONFIRMED")

    def test_content_probe_not_masked_by_policy_rule(self):
        """S3 私钥探测不被 S2 的 internal 规则掩盖。"""
        scope = load_scope()
        ident = resolve_path(
            "/papers/paper-a.pdf",
            version_id="inode:77:1",
            content_probe="-----BEGIN RSA PRIVATE KEY-----",
        )
        verdict = infer_sensitivity(ident, scope)
        self.assertEqual(verdict.level, "secret")

    def test_path_prior_raises_only(self):
        scope = load_scope()
        ident = resolve_path("/home/user/.ssh/id_rsa", version_id="inode:99:1")
        verdict = infer_sensitivity(ident, scope)
        self.assertEqual(verdict.level, "secret")
        self.assertEqual(verdict.source, "S4_path_prior")


class TestSchemaVersionEnforcement(unittest.TestCase):
    def test_wrong_schema_version_rejected(self):
        with self.assertRaises(ValueError):
            DataScope.from_dict({"schemaVersion": "wrong.v9", "taskId": "t"})


class TestEventShape(unittest.TestCase):
    """事件结构符合 first-read.v1 schema 的必填字段。"""

    def test_event_required_fields(self):
        gate = FirstReadGate(load_scope())
        event = gate.request_read(
            resolve_path("/papers/paper-a.pdf", version_id="inode:77:1"),
            ReadRequest(requested_bytes=1000),
            span_id="tool-call-7ab2",
            execution={"pid": 4242, "processInstanceId": "hostA:4242:1"},
            actor={"type": "subagent", "id": "agent://reader"},
        )
        for key in (
            "schemaVersion", "eventId", "taskId", "actor", "resource",
            "read", "sensitivity", "decision",
        ):
            self.assertIn(key, event)
        self.assertEqual(event["schemaVersion"], "agentos.first-read.v1")
        self.assertEqual(event["spanId"], "tool-call-7ab2")
        self.assertEqual(event["actor"]["type"], "subagent")
        self.assertEqual(event["execution"]["pid"], 4242)


if __name__ == "__main__":
    unittest.main(verbosity=2)
