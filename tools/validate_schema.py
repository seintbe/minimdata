"""最小化的 JSON Schema 校验器，覆盖本项目 schema 使用的关键字子集。

支持：$ref（本地 #/$defs）、type、required、enum、const、properties、
additionalProperties、items、pattern、minimum、minLength。

不使用第三方依赖，便于在无网络环境下复算验收结论。
运行：python tools/validate_schema.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


class SchemaError(Exception):
    pass


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaError(f"unsupported external $ref: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _check_type(value: Any, expected: Any) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        py = TYPE_MAP.get(name)
        if py is None:
            continue
        # bool 是 int 的子类，需显式排除，否则 True 会被当作 integer
        if py is int and isinstance(value, bool):
            continue
        if isinstance(value, py):
            return True
    return False


def validate(
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
    errors: list[str] | None = None,
) -> list[str]:
    if errors is None:
        errors = []

    if "$ref" in schema:
        return validate(instance, _resolve_ref(root, schema["$ref"]), root, path, errors)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")

    if "type" in schema and not _check_type(instance, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']}, got {type(instance).__name__}")
        return errors

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern {schema['pattern']!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                validate(value, props[key], root, f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key!r}")
        for key, sub in props.items():
            if key not in instance and "default" in sub:
                pass

    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            validate(item, schema["items"], root, f"{path}[{i}]", errors)

    return errors


def load(path: Path) -> Any:
    return json.loads(path.read_text("utf-8"))


def main() -> int:
    failures = 0

    scope_schema = load(ROOT / "schema" / "data-scope.schema.json")
    event_schema = load(ROOT / "schema" / "first-read-event.schema.json")

    # 1. 示例策略须符合 data-scope schema
    scope = load(ROOT / "examples" / "data-scope.summarize-paper.json")
    errs = validate(scope, scope_schema, scope_schema)
    print(f"data-scope.summarize-paper.json : {'OK' if not errs else 'FAIL'}")
    for e in errs:
        print("   ", e)
    failures += len(errs)

    # 2. 演示输出的每个首读事件须符合 first-read schema
    payload = load(ROOT / "examples" / "demo-output.json")
    events = payload["firstReadEvents"]
    total = 0
    for i, event in enumerate(events):
        errs = validate(event, event_schema, event_schema, path=f"$[{i}]")
        total += len(errs)
        for e in errs:
            print("   ", e)
    print(f"demo-output.json ({len(events)} events) : {'OK' if not total else 'FAIL'}")
    failures += total

    # 3. 负面用例：非法事件必须被拒，验证校验器本身有效
    bad_event = dict(events[0])
    bad_event["decision"] = {"verdict": "MAYBE", "reason": "x", "decisionId": "y"}
    errs = validate(bad_event, event_schema, event_schema)
    if errs:
        print("negative case (bad verdict)     : OK (rejected)")
    else:
        print("negative case (bad verdict)     : FAIL (validator too weak)")
        failures += 1

    print()
    if failures:
        print(f"FAILURES: {failures}")
        return 1
    print("ALL SCHEMA VALIDATIONS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
