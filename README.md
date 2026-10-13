# 最小数据 · AgentOS 安全架构

一个任务在开始执行之前，应该允许多少信息进入它的上下文？本分册只回答这个问题。
判定对象是「任务—资源—首次读取」，不含目的地、传播路径与用途义务。

## 目录

| 路径 | 说明 |
| --- | --- |
| `最小数据.md` | 设计方案主文档 |
| `schema/data-scope.schema.json` | 任务输入面声明（`DataScope`）的 JSON Schema |
| `schema/first-read-event.schema.json` | 首次读取事件（`FirstReadEvent`）的 JSON Schema |
| `src/minimal_data.py` | 参考实现：六步判定、读折叠、敏感度推定、失败关闭 |
| `examples/data-scope.summarize-paper.json` | 示例策略：总结论文并生成邮件草稿 |
| `examples/demo.py` | 端到端演示，输出 `examples/demo-output.json` |
| `tests/test_minimal_data.py` | 验收测试，31 项 |
| `tools/validate_schema.py` | 无第三方依赖的 JSON Schema 校验器与一致性检查 |

## 复算

```bash
python tests/test_minimal_data.py        # 31 项验收测试
python examples/demo.py                  # 生成演示轨迹
python tools/validate_schema.py          # schema 校验（含负面用例）
```

三项命令均应无失败退出。`tools/validate_schema.py` 内含一个负面用例，用于证明校验器本身
能够拒绝非法事件 —— 只报「通过」的校验器不构成证据。

## 与前置分册的关系

本机制与最小权限分册是**判定位置的前后串联**，不是替代关系：

```text
用户任务
  └─ DataScope 生成（声明输入清单）
       └─ FirstReadEvent × N        ← 本分册到此为止
            └─ prompt 组装
                 └─ 模型请求
                      └─ 响应
                           └─ 写入  ← 最小权限 / 信息流分册
```

最小数据在执行前削减可能的源集合（一个顶点是否可入），最小权限对剩下的源约束其去向
（一条边是否被允许）。两者的判定逻辑彼此独立，可分别复现。

## 三条失败关闭规则

1. 采集缺口不判为安全 —— 一律 `UNKNOWN`，不进入放行分支。
2. 敏感度未知不判为公开 —— `REVIEW` 或 `DENY`，绝不 `ALLOW`。
3. 声明缺失不判为可选 —— 未列出的资源为 `DENY`。

## 已知边界

- 不回答数据去哪里，已被允许进入的信息面其后续流向由最小权限分册处理。
- 依赖 `DataScope` 的准确性：若由自然语言任务自动生成，其质量即为机制上限。
- 判定与读取之间存在 TOCTOU 窗口，缓解手段是按 inode 与打开后的 FD 校验。
- 参考实现不含真实系统调用采集，消费的是 Transpect 三层归一化后的事件。
