"""端到端演示：为一个「总结论文并生成邮件草稿」任务运行首次读取门。

产生一份可核验的 FirstReadEvent 序列与信息面报告，写入 examples/demo-output.json。
运行：python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from minimal_data import (  # noqa: E402
    DataScope,
    FirstReadGate,
    ReadRequest,
    resolve_path,
)


def main() -> int:
    scope_raw = json.loads(
        (ROOT / "examples" / "data-scope.summarize-paper.json").read_text("utf-8")
    )
    scope = DataScope.from_dict(scope_raw)
    gate = FirstReadGate(scope)

    # 一个主 Agent 加两个子 Agent 的读取序列。
    scenarios = [
        # (资源路径, 软链目标, 版本, 请求字节, 读上下文, 覆盖缺口)
        (
            "/papers/paper-a.pdf", None, "inode:77:1", 40960,
            {"actor": {"type": "agent", "id": "agent://main"}, "span_id": "span-t1"},
            [],
        ),
        (
            "/papers/paper-a.pdf", None, "inode:77:1", 20480,
            {"actor": {"type": "agent", "id": "agent://main"}, "span_id": "span-t2"},
            [],
        ),
        (
            "/papers/paper-a.pdf", None, "inode:77:1", 262144,
            {"actor": {"type": "subagent", "id": "agent://reader"}, "span_id": "span-t3"},
            [],
        ),
        (
            "/templates/mail/welcome.md", None, "inode:31:1", 4096,
            {"actor": {"type": "agent", "id": "agent://main"}, "span_id": "span-t4"},
            [],
        ),
        (
            "/home/user/.ssh/id_rsa", None, "inode:99:1", 2048,
            {"actor": {"type": "subagent", "id": "agent://curious"}, "span_id": "span-t5"},
            [],
        ),
        (
            "/papers/current/notes.md", "/etc/passwd", "inode:12:1", 4096,
            {"actor": {"type": "subagent", "id": "agent://curious"}, "span_id": "span-t6"},
            [],
        ),
        (
            "/papers/2026/paper-b.pdf", None, "inode:5:1", 8192,
            {"actor": {"type": "agent", "id": "agent://main"}, "span_id": "span-t7"},
            [],
        ),
        (
            "/templates/mail/release.md", None, "inode:32:1", 4096,
            {"actor": {"type": "tool", "id": "tool://mailer"}, "span_id": "span-t8"},
            ["frida_not_attached"],
        ),
        (
            "/papers/paper-a.pdf", None, "inode:77:2", 40960,
            {"actor": {"type": "agent", "id": "agent://main"}, "span_id": "span-t9"},
            [],
        ),
    ]

    for path, link, version, nbytes, ctx, gaps in scenarios:
        ident = resolve_path(path, link_target=link, version_id=version)
        gate.request_read(
            ident,
            ReadRequest(requested_bytes=nbytes, coverage_gaps=gaps),
            actor=ctx["actor"],
            span_id=ctx["span_id"],
        )

    report = gate.audit_report(declared_count=len(scope.declared_inputs))
    payload = {
        "taskId": scope.task_id,
        "summary": scope.summary,
        "firstReadEvents": gate.events,
        "auditReport": report,
    }
    out = ROOT / "examples" / "demo-output.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"taskId            : {scope.task_id}")
    print(f"declaredInputs    : {report['declaredInputs']}")
    print(f"inputSurface      : {report['inputSurface']}")
    print(f"verdicts          : {report['verdicts']}")
    print(f"coverageGapEvents : {report['coverageGapEvents']}")
    print(f"written           : {out}")
    print()
    for event in gate.events:
        actor = event["actor"]["id"]
        path = event["resource"]["resolvedPath"]
        verdict = event["decision"]["verdict"]
        reason = event["decision"]["reason"]
        # 只有 ALLOW / TRUNCATE 让内容进入任务上下文，其余裁决不表示任何授予
        granted = (
            f"{event['read']['grantedBytes']}B"
            if verdict in ("ALLOW", "TRUNCATE")
            else "-"
        )
        print(f"  {verdict:<8} {path:<32} {granted:>8}  {reason:<42} {actor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
