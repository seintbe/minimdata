"""最小数据：AgentOS 的输入面收敛机制。

参考实现。覆盖设计文档 `最小数据.md` 的：
  - 4.2 六步判定算法
  - 4.3 重复读取折叠
  - 3.2 四级敏感度推定
  - 6.1 三条失败关闭规则

不包含真实系统调用采集：采集由 Transpect 的 app/runtime/system 三层提供，
本模块消费归一化后的事件并产生 FirstReadEvent。
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

SCHEMA_VERSION_SCOPE = "agentos.data-scope.v1"
SCHEMA_VERSION_EVENT = "agentos.first-read.v1"

# 敏感度格。UNKNOWN 不可比较：它既不是最高也不是最低，必须单独判定。
SENSITIVITY_ORDER = ["public", "internal", "confidential", "secret"]
SENSITIVITY_UNKNOWN = "UNKNOWN"

CONFIDENCE_ORDER = ["UNKNOWN", "INFERRED", "CORROBORATED", "CONFIRMED"]

# 推定来源分级，数字越大越可靠。取最高级别来源作为结论。
SOURCE_RANK = {
    "none": 0,
    "S4_path_prior": 1,
    "S3_content": 2,
    "S2_policy": 3,
    "S1_explicit": 4,
}

VERDICT_ALLOW = "ALLOW"
VERDICT_DENY = "DENY"
VERDICT_TRUNCATE = "TRUNCATE"
VERDICT_REVIEW = "REVIEW"
VERDICT_UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------
# 资源身份
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceIdentity:
    """解析后的资源身份。策略匹配只在 resolved_path 上执行，避免软链绕过前缀。"""

    resource_id: str
    resolved_path: str
    origin_path: str
    version_id: str | None = None
    size_bytes: int | None = None
    content_fingerprint: str | None = None
    link_chain: tuple[str, ...] = ()
    explicit_sensitivity: str | None = None
    unresolved: bool = False
    content_probe: str | None = None

    def key(self) -> tuple[str, str]:
        """折叠键：同任务同版本视为同一信息面。"""
        return (self.resource_id, self.version_id or "")


def normalize_resource_id(path: str) -> str:
    """file: 资源做路径规范化；其余 scheme 原样保留。"""
    if path.startswith("file:"):
        raw = path[len("file:") :]
        return "file:" + (posixpath.normpath(raw) if raw else raw)
    return path


# --------------------------------------------------------------------------
# 路径匹配：大小写无关的确定性 glob
# --------------------------------------------------------------------------

_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_to_regex(pattern: str, *, recursive: bool) -> re.Pattern[str]:
    """把 glob 编译为正则。

    `*`  匹配单个路径段内的任意字符，不跨越 `/`。
    `**` 跨路径段匹配，仅在 recursive=True 时生效；否则与 `*` 等价（不下钻）。
    `?`  匹配单个非 `/` 字符。
    """
    key = f"{pattern}|{recursive}"
    cached = _GLOB_CACHE.get(key)
    if cached is not None:
        return cached

    out: list[str] = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                if recursive:
                    out.append(".*")
                else:
                    out.append("[^/]*")
                i += 2
                # 吸收 `**/` 形式，使其可匹配零级目录
                if i < n and pattern[i] == "/":
                    out.append("/?")
                    i += 1
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")

    compiled = re.compile("".join(out), re.IGNORECASE)
    _GLOB_CACHE[key] = compiled
    return compiled


def glob_match(pattern: str, value: str, *, recursive: bool = False) -> bool:
    return bool(_glob_to_regex(pattern, recursive=recursive).match(value))


def crosses_directory(resolved_path: str, entry_pattern: str) -> bool:
    """判断 resolved_path 是否位于 entry_pattern 所指目录之下。

    用于 non-recursive glob 的下钻检测：`file:/papers/*` 不应匹配
    `/papers/2026/paper-a.pdf`。
    """
    base = entry_pattern.rstrip("*").rstrip("/")
    if not base:
        return False
    if not resolved_path.lower().startswith(base.lower()):
        return False
    tail = resolved_path[len(base) :].lstrip("/")
    return "/" in tail


# --------------------------------------------------------------------------
# DataScope
# --------------------------------------------------------------------------


@dataclass
class DeclaredInput:
    input_id: str
    resource: str
    match: str
    necessity: str
    max_bytes: int | None = None
    sensitivity_ceiling: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DeclaredInput":
        return cls(
            input_id=raw["inputId"],
            resource=normalize_resource_id(raw["resource"]),
            match=raw["match"],
            necessity=raw["necessity"],
            max_bytes=raw.get("maxBytes"),
            sensitivity_ceiling=raw.get("sensitivityCeiling"),
        )


@dataclass
class SensitivityRule:
    rule_id: str
    pattern: str
    level: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SensitivityRule":
        return cls(rule_id=raw["ruleId"], pattern=raw["pattern"], level=raw["level"])


@dataclass
class DataScope:
    task_id: str
    declared_inputs: list[DeclaredInput] = field(default_factory=list)
    sensitivity_rules: list[SensitivityRule] = field(default_factory=list)
    unlisted_resource: str = "DENY"
    recursive_glob: bool = False
    allow_sensitive_upgrade: bool = False
    strict_mode: bool = False
    summary: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DataScope":
        if raw.get("schemaVersion") != SCHEMA_VERSION_SCOPE:
            raise ValueError(
                f"unsupported schemaVersion: {raw.get('schemaVersion')!r}, "
                f"expected {SCHEMA_VERSION_SCOPE!r}"
            )
        defaults = raw.get("defaults") or {}
        return cls(
            task_id=raw["taskId"],
            summary=raw.get("summary", ""),
            declared_inputs=[
                DeclaredInput.from_dict(item) for item in raw.get("declaredInputs", [])
            ],
            sensitivity_rules=[
                SensitivityRule.from_dict(item)
                for item in raw.get("sensitivityRules", [])
            ],
            unlisted_resource=defaults.get("unlistedResource", "DENY"),
            recursive_glob=bool(defaults.get("recursiveGlob", False)),
            allow_sensitive_upgrade=bool(defaults.get("allowSensitiveUpgrade", False)),
            strict_mode=bool(defaults.get("strictMode", False)),
        )

    def match(self, identity: ResourceIdentity) -> DeclaredInput | None:
        """按声明顺序返回第一个命中的条目。

        exact 匹配解析后路径全等；glob 在解析后路径上执行。
        非递归 glob 不下钻目录（4.2 第 3 步）。
        """
        target = identity.resolved_path
        for entry in self.declared_inputs:
            pattern = entry.resource
            if pattern.startswith("file:"):
                pattern = pattern[len("file:") :]
                if not target.startswith("/") and pattern.startswith("/"):
                    pattern = pattern.lstrip("/")
                if entry.match == "exact":
                    if pattern.lower() == target.lower():
                        return entry
                    continue
                if crosses_directory(target, pattern) and not self.recursive_glob:
                    continue
                if glob_match(pattern, target, recursive=self.recursive_glob):
                    return entry
                continue

            # 非 file 资源：scheme 前缀匹配 + glob
            scheme, _, rest = pattern.partition(":")
            if not identity.resource_id.lower().startswith(scheme.lower() + ":"):
                continue
            value = identity.resource_id.split(":", 1)[1]
            if entry.match == "exact":
                if rest.lower() == value.lower():
                    return entry
                continue
            if glob_match(rest, value, recursive=True):
                return entry
        return None


# --------------------------------------------------------------------------
# 敏感度推定（3.2）
# --------------------------------------------------------------------------

# S3 内容探测模式。命中即提升敏感度。
_CONTENT_PATTERNS: list[tuple[str, str]] = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "secret"),
    (r"\bAKIA[0-9A-Z]{16}\b", "secret"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "secret"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "secret"),
    (r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]", "confidential"),
]

# S4 目录先验。
_PATH_PRIORS: list[tuple[str, str]] = [
    ("**/.ssh/**", "secret"),
    ("**/.aws/**", "secret"),
    ("**/.env", "confidential"),
    ("**/id_rsa*", "secret"),
    ("/etc/**", "confidential"),
    ("**/.credentials*", "secret"),
]


@dataclass
class SensitivityVerdict:
    level: str
    source: str
    confidence: str
    matched_rule: str | None = None


def _max_level(levels: Iterable[str]) -> str:
    best = None
    for lv in levels:
        if lv == SENSITIVITY_UNKNOWN or lv not in SENSITIVITY_ORDER:
            continue
        if best is None or SENSITIVITY_ORDER.index(lv) > SENSITIVITY_ORDER.index(best):
            best = lv
    return best or SENSITIVITY_UNKNOWN


def infer_sensitivity(
    identity: ResourceIdentity, scope: DataScope
) -> SensitivityVerdict:
    """四级推定，取最高级别。

    S1 显式标注 > S2 策略规则 > S3 内容探测 > S4 目录先验。
    S3 与 S4 只能提升敏感度，不能降低——未命中不等于公共（3.2 节约束）。
    四级全部未命中时为 UNKNOWN，而非 public。
    """
    candidates: list[tuple[int, str, str, str | None]] = []

    # S1 显式标注
    if identity.explicit_sensitivity:
        lv = identity.explicit_sensitivity
        if lv == SENSITIVITY_UNKNOWN or lv not in SENSITIVITY_ORDER:
            # 显式标注为 UNKNOWN 时按未知处理，不降级为 public
            candidates.append((SOURCE_RANK["S1_explicit"], SENSITIVITY_UNKNOWN, "UNKNOWN", "explicit:unknown"))
        else:
            candidates.append(
                (SOURCE_RANK["S1_explicit"], lv, "CONFIRMED", "explicit:metadata")
            )

    # S2 策略规则
    for rule in scope.sensitivity_rules:
        pattern = rule.pattern
        if pattern.startswith("file:"):
            pattern = pattern[len("file:") :]
        if glob_match(pattern, identity.resolved_path, recursive=True):
            candidates.append(
                (
                    SOURCE_RANK["S2_policy"],
                    rule.level,
                    "CORROBORATED",
                    rule.rule_id,
                )
            )

    # S3 内容探测
    if identity.content_probe:
        for pattern, level in _CONTENT_PATTERNS:
            if re.search(pattern, identity.content_probe):
                candidates.append(
                    (SOURCE_RANK["S3_content"], level, "INFERRED", f"content:{pattern[:24]}")
                )

    # S4 目录先验
    for pattern, level in _PATH_PRIORS:
        if glob_match(pattern, identity.resolved_path, recursive=True):
            candidates.append(
                (SOURCE_RANK["S4_path_prior"], level, "INFERRED", f"path:{pattern}")
            )

    if not candidates:
        return SensitivityVerdict(SENSITIVITY_UNKNOWN, "none", "UNKNOWN", None)

    # 取所有来源中**最高敏感级别**，而非最高来源级别。
    # 来源分级只用于记录该结论由谁证明：一条声明 /papers/** 为 internal 的规则
    # 不得掩盖同目录文件中探测到的私钥。S3/S4 只提升不降低的约束由此自然满足。
    level = _max_level([c[1] for c in candidates])
    if level == SENSITIVITY_UNKNOWN:
        return SensitivityVerdict(SENSITIVITY_UNKNOWN, "none", "UNKNOWN", None)

    # 在得出该级别的候选中，取来源可靠度最高者作为证明来源
    proving = [c for c in candidates if c[1] == level]
    chosen = max(proving, key=lambda c: c[0])
    return SensitivityVerdict(level, _rank_to_source(chosen[0]), chosen[2], chosen[3])


def _rank_to_source(rank: int) -> str:
    for name, value in SOURCE_RANK.items():
        if value == rank and name != "none":
            return name
    return "none"


def _level_exceeds(level: str, ceiling: str | None) -> bool:
    """level 是否高于 ceiling。UNKNOWN 视为不能证明低于天花板。"""
    if ceiling is None:
        return False
    if level == SENSITIVITY_UNKNOWN or ceiling == SENSITIVITY_UNKNOWN:
        return True
    if level not in SENSITIVITY_ORDER or ceiling not in SENSITIVITY_ORDER:
        return True
    return SENSITIVITY_ORDER.index(level) > SENSITIVITY_ORDER.index(ceiling)


# --------------------------------------------------------------------------
# 判定
# --------------------------------------------------------------------------


@dataclass
class ReadRequest:
    requested_bytes: int
    offset: int = 0
    coverage_gaps: list[str] = field(default_factory=list)


class FirstReadGate:
    """首次读取门。

    一个任务对一个资源版本至多产生一个 FirstReadEvent。重复读取被折叠（4.3）。
    """

    def __init__(self, scope: DataScope) -> None:
        self.scope = scope
        self._events: list[dict[str, Any]] = []
        self._granted: dict[tuple[str, str], int] = {}

    # -- 判定核心（4.2 六步） --------------------------------------------
    def judge(
        self,
        identity: ResourceIdentity,
        request: ReadRequest,
        *,
        actor: dict[str, str] | None = None,
        execution: dict[str, Any] | None = None,
        span_id: str | None = None,
        evidence_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        actor = actor or {"type": "agent", "id": "agent://main"}
        execution = execution or {}
        evidence_refs = evidence_refs or []

        # 第 1 步：解析资源身份
        if identity.unresolved:
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=VERDICT_UNKNOWN,
                reason="resource_identity_unresolved",
                matched_input_id=None,
                sensitivity=SensitivityVerdict(SENSITIVITY_UNKNOWN, "none", "UNKNOWN", None),
            )

        # 第 2 步：命中声明清单
        entry = self.scope.match(identity)
        if entry is None:
            verdict = (
                VERDICT_REVIEW if self.scope.unlisted_resource == "REVIEW" else VERDICT_DENY
            )
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=verdict,
                reason="resource_not_declared",
                matched_input_id=None,
                sensitivity=infer_sensitivity(identity, self.scope),
            )

        # 第 3 步：glob 语义与必要性
        if entry.match == "glob" and not self.scope.recursive_glob:
            pattern = entry.resource
            if pattern.startswith("file:"):
                pattern = pattern[len("file:") :]
            if crosses_directory(identity.resolved_path, pattern):
                return self._emit(
                    identity, request, actor, execution, span_id, evidence_refs,
                    verdict=VERDICT_DENY,
                    reason="glob_not_recursive",
                    matched_input_id=entry.input_id,
                    sensitivity=infer_sensitivity(identity, self.scope),
                )
        if entry.necessity == "required" and identity.version_id is None:
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=VERDICT_DENY,
                reason="required_input_unavailable",
                matched_input_id=entry.input_id,
                sensitivity=infer_sensitivity(identity, self.scope),
            )

        # 第 4 步：敏感度推定与天花板
        sens = infer_sensitivity(identity, self.scope)
        if sens.level == SENSITIVITY_UNKNOWN:
            # 未知敏感度绝不放行（6.1 规则 2）。先于天花板判定，
            # 否则会被误报为 ceiling_exceeded，掩盖真实的未知状态。
            verdict = VERDICT_DENY if self.scope.strict_mode else VERDICT_REVIEW
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=verdict,
                reason="sensitivity_unknown",
                matched_input_id=entry.input_id,
                sensitivity=sens,
            )
        if _level_exceeds(sens.level, entry.sensitivity_ceiling):
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=VERDICT_DENY,
                reason="sensitivity_ceiling_exceeded",
                matched_input_id=entry.input_id,
                sensitivity=sens,
            )

        # 第 5 步：采集覆盖（6.1 规则 1）
        if request.coverage_gaps:
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=VERDICT_UNKNOWN,
                reason="collector_gap",
                matched_input_id=entry.input_id,
                sensitivity=sens,
            )

        # 第 6 步：字节预算
        if entry.max_bytes is not None and request.requested_bytes > entry.max_bytes:
            return self._emit(
                identity, request, actor, execution, span_id, evidence_refs,
                verdict=VERDICT_TRUNCATE,
                reason="byte_budget_exceeded",
                matched_input_id=entry.input_id,
                sensitivity=sens,
                granted_override=entry.max_bytes,
            )

        return self._emit(
            identity, request, actor, execution, span_id, evidence_refs,
            verdict=VERDICT_ALLOW,
            reason="declared_input_within_scope",
            matched_input_id=entry.input_id,
            sensitivity=sens,
        )

    # -- 折叠（4.3） ------------------------------------------------------
    def request_read(
        self,
        identity: ResourceIdentity,
        request: ReadRequest,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """对外的读取入口，施加折叠语义。"""
        if identity.unresolved:
            return self.judge(identity, request, **kwargs)

        key = identity.key()
        prior = self._granted.get(key)

        if prior is not None:
            # 同版本重读：范围已被授予则不新增事件
            if request.requested_bytes <= prior:
                return {
                    "schemaVersion": SCHEMA_VERSION_EVENT,
                    "taskId": self.scope.task_id,
                    "eventId": None,
                    "folded": True,
                    "decision": {
                        "verdict": VERDICT_ALLOW,
                        "reason": "repeat_read_within_granted_range",
                        "decisionId": _stable_id("frdec", self.scope.task_id, key, "folded"),
                        "matchedInputId": None,
                    },
                }
            # 范围扩大：重跑判定
            event = self.judge(identity, request, **kwargs)
            event["folded"] = False
            event["decision"]["reason"] = (
                "scope_extension:" + event["decision"]["reason"]
            )
            return event

        # 首次：完整判定
        event = self.judge(identity, request, **kwargs)
        event["folded"] = False
        return event

    # -- 内部 -------------------------------------------------------------
    def _emit(
        self,
        identity: ResourceIdentity,
        request: ReadRequest,
        actor: dict[str, str],
        execution: dict[str, Any],
        span_id: str | None,
        evidence_refs: list[str],
        *,
        verdict: str,
        reason: str,
        matched_input_id: str | None,
        sensitivity: SensitivityVerdict,
        granted_override: int | None = None,
    ) -> dict[str, Any]:
        granted = granted_override if granted_override is not None else request.requested_bytes
        truncated = granted < request.requested_bytes

        event = {
            "schemaVersion": SCHEMA_VERSION_EVENT,
            "eventId": _stable_id(
                "fr", self.scope.task_id, identity.resource_id, identity.version_id or "-",
                len(self._events),
            ),
            "taskId": self.scope.task_id,
            "spanId": span_id,
            "actor": actor,
            "execution": execution,
            "resource": {
                "resourceId": identity.resource_id,
                "versionId": identity.version_id,
                "contentFingerprint": identity.content_fingerprint,
                "sizeBytes": identity.size_bytes,
                "originPath": identity.origin_path,
                "resolvedPath": identity.resolved_path,
                "linkChain": list(identity.link_chain),
            },
            "read": {
                "requestedBytes": request.requested_bytes,
                "grantedBytes": granted,
                "offset": request.offset,
                "truncated": truncated,
            },
            "sensitivity": {
                "level": sensitivity.level,
                "source": sensitivity.source,
                "confidence": sensitivity.confidence,
                "matchedRule": sensitivity.matched_rule,
            },
            "decision": {
                "verdict": verdict,
                "matchedInputId": matched_input_id,
                "reason": reason,
                "decisionId": _stable_id(
                    "frdec", self.scope.task_id, identity.resource_id, reason
                ),
            },
            "coverageGaps": list(request.coverage_gaps),
            "evidenceRefs": list(evidence_refs),
        }

        # 只有放行与截断让内容进入任务上下文，此时登记授予范围
        if verdict in (VERDICT_ALLOW, VERDICT_TRUNCATE) and identity.version_id is not None:
            self._granted[identity.key()] = granted

        self._events.append(event)
        return event

    # -- 信息面度量（4.4） ------------------------------------------------
    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def input_surface(self) -> int:
        """一个任务的信息面大小 = 其 FirstReadEvent 数量。"""
        return len(self._events)

    def granted_resources(self) -> set[tuple[str, str]]:
        return set(self._granted)

    def audit_report(self, declared_count: int) -> dict[str, Any]:
        """最小数据合规性度量：实际读取资源数 / 声明资源数。"""
        surface = self.input_surface()
        ratio = (surface / declared_count) if declared_count else None
        by_verdict: dict[str, int] = {}
        for event in self._events:
            v = event["decision"]["verdict"]
            by_verdict[v] = by_verdict.get(v, 0) + 1
        return {
            "taskId": self.scope.task_id,
            "declaredInputs": declared_count,
            "inputSurface": surface,
            "inputSurfaceRatio": ratio,
            "verdicts": by_verdict,
            "coverageGapEvents": sum(1 for e in self._events if e.get("coverageGaps")),
        }


def _stable_id(prefix: str, *parts: Any) -> str:
    joined = "|".join(str(p) for p in parts if p is not None)
    digest = hashlib.sha1(joined.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{prefix}-{digest}"


# --------------------------------------------------------------------------
# 便捷构造
# --------------------------------------------------------------------------


def resolve_path(
    path: str,
    *,
    link_target: str | None = None,
    version_id: str | None = None,
    size_bytes: int | None = None,
    content_probe: str | None = None,
    explicit_sensitivity: str | None = None,
) -> ResourceIdentity:
    """构造一个已解析的资源身份。真实部署中由采集层提供 link_target。"""
    origin = path
    resolved = link_target or path
    chain = (origin, resolved) if link_target and link_target != origin else (origin,)
    return ResourceIdentity(
        resource_id=normalize_resource_id("file:" + resolved),
        resolved_path=resolved,
        origin_path=origin,
        version_id=version_id,
        size_bytes=size_bytes,
        content_probe=content_probe,
        explicit_sensitivity=explicit_sensitivity,
        link_chain=chain,
    )
