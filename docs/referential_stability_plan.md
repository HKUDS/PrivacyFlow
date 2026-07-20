# APG 上下文引用稳定性收敛计划

状态：本地实施计划，暂不提交。

## 1. 背景

真实 OpenCode 场景暴露了一个比工具权限更核心的问题：APG 提供给远程模型的对象表示不具备稳定引用语义。

失败链路如下：

1. workspace 根目录和其 `scripts/` 子目录曾被映射为两个互不相关的 alias。
2. Agent 因路径语义不连续而反复探测，并经历工具路径或权限失败。
3. 同一 secret/PII 在多轮请求中被重新签发为带不同 `issued_at` 和 MAC 的 placeholder。
4. 已存在于对话历史中的 marker 再次进入请求扫描时，可能被当作普通敏感文本重新包装。
5. 模型最终输出了格式正确但 session/MAC 不正确的 marker；APG 正确 fail-closed，但工具任务失败。

这说明当前实现守住了保密性，却没有完全守住引用完整性、重试稳定性和可用性。最终自然场景通过不能替代对强制失败、延迟、多轮重放和服务重启的确定性验证。

## 2. 责任边界

本计划只解决 APG 核心数据转换与状态问题。

APG 负责：

- 为同一 mapping 提供稳定、可验证的远程标识。
- 对合法 marker 做幂等处理，不嵌套包装。
- 对无效、跨 session、跨 workspace、过期和 tombstone marker 稳定 fail-closed。
- 保持路径 alias 的层级、session/workspace 作用域和重启恢复能力。
- 在 Chat Completions、Anthropic Messages 和 Responses 的流式/非流式路径上保持相同行为。
- 输出不包含原始敏感值和 marker 内容的安全审计事件。

Harness 继续负责：

- Read/Bash/Edit/Write 等工具权限。
- 命令 allowlist、网络审批和本地文件写入策略。
- 是否执行一个已经 materialize 的工具调用。
- 本地 Agent trajectory 的访问、保留和清理。

本计划不会把工具审批、命令审查或文件写入防火墙重新放回 APG。

## 3. 必须建立的系统不变量

### 3.1 Canonical placeholder

同一有效 mapping：

```text
(session_id, workspace_id, kind, handle_id, policy_hash)
```

在其生命周期内必须对应唯一的 canonical placeholder。刷新 idle TTL、重复检测相同值、跨请求重现以及服务重启都不得改变 marker。

### 3.2 请求幂等性

对任意请求正文 `x`，在 mapping 状态不变时应满足：

```text
sanitize(sanitize(x)) == sanitize(x)
```

合法 canonical marker 再次进入请求时必须保持不变。合法但属于旧签发策略的 marker 应收敛到当前 canonical marker，而不是被包装成新的 secret mapping。

### 3.3 无嵌套 marker

任何输入都不得产生以下语义：

```text
placeholder(raw_placeholder)
```

无效 marker 不能作为普通 secret 保存到 mapping store，也不能生成新的 `<APG:v1:...>`。

### 3.4 稳定失败

无效 marker 必须得到稳定、非重试型结果：

- `APG_PLACEHOLDER_INVALID_MAC`
- `APG_PLACEHOLDER_SCOPE_MISMATCH`
- `APG_PLACEHOLDER_EXPIRED`
- `APG_PLACEHOLDER_TOMBSTONED`
- `APG_PLACEHOLDER_UNRESOLVED`
- `APG_PLACEHOLDER_POLICY_MISMATCH`，如引入 policy 版本校验

同一无效输入重复出现时，结果码不得变化，不得创建 mapping，不得延长 TTL，也不得诱发嵌套 marker。

### 3.5 路径可组合性

父路径已映射后，子路径必须复用父 alias：

```text
/private/.../repo
  -> /workspace/repo-<hash>

/private/.../repo/scripts/validate_secret.py
  -> /workspace/repo-<hash>/scripts/validate_secret.py
```

不得再次生成 `/workspace/scripts-<other-hash>`。句末标点、JSON 引号和 SSE 分片不得进入路径 mapping。

### 3.6 协议一致性

以下路径必须共享同一 canonicalization 和验证语义：

- `/v1/chat/completions` 非流式与流式
- `/v1/messages` 非流式与流式
- `/v1/responses` 非流式与流式
- 可见文本、reasoning summary、refusal、tool/function arguments 和最终 snapshot

## 4. 当前根因

### 4.1 Marker 每次按当前时间签发

`PlaceholderSigner.issue()` 默认使用 `time.time()`。虽然 `MappingStore.upsert_mapping()` 会复用同一 `handle_id`，但每次调用仍可能生成新的 `issued_at` 和 MAC。

因此，同一逻辑对象会出现多个远程字符串表示。旧 marker 在 mapping TTL 内仍可验证，所以这种轮换没有缩短实际授权窗口，只增加了模型上下文歧义。

### 4.2 Signed marker 进入通用 detector 流程

请求扫描会把 `signed_placeholder` 归入 secret 类别。当前缺少一个在通用 redaction 前执行的 marker canonicalization 阶段，因此合法 marker 可能被再次 upsert 和包装。

### 4.3 Mapping 缺少显式 canonical 签发字段

Mapping 已有稳定的 `created_at`、`handle_id` 和 `policy_hash`，但没有显式记录 canonical marker 的签发时间。直接依赖调用时钟使表示层与 mapping 生命周期脱节。

### 4.4 路径层级曾丢失

当前已实现父 alias 加相对 suffix，但仍需要补充跨请求、并发和重启测试，确保未来修改不会恢复为 basename-only alias。

## 5. 推荐设计

### 5.1 在 mapping 中保存 canonical 签发时间

为 `mappings` 表增加：

```sql
placeholder_issued_at INTEGER NOT NULL
```

规则：

- 新 mapping：`placeholder_issued_at = created_at`。
- 重复 upsert：只更新 `last_seen_at` 和 `idle_expires_at`，不得修改 `placeholder_issued_at`。
- tombstone 后同值重新建立 mapping：生成新 `handle_id` 和新 `placeholder_issued_at`。
- 服务重启：从 SQLite 恢复相同字段，重新计算出完全相同的 marker。

不建议直接持久化完整 marker。marker 可以由稳定字段和 signing secret 确定性计算，避免数据库保存冗余认证数据。

### 5.2 提供 record-aware 签发 API

新增类似接口：

```python
signer.issue_for_record(record)
```

它必须使用：

- `record.kind`
- `record.handle_id`
- `record.session_id`
- `record.placeholder_issued_at`
- `record.policy_hash`
- 当前 workspace/signing key

所有 redaction 路径必须通过这个接口生成 marker，禁止业务代码直接使用当前时间调用 `issue()`。

### 5.3 在通用检测前增加 marker canonicalization pass

对每个字符串先解析所有 `<APG:v1:...>` candidate，并将其 span 从后续通用 detector 中保护起来。

处理矩阵：

| Marker 状态 | 请求上行处理 | 下行结构化工具参数处理 |
|---|---|---|
| 当前 canonical 且 scope 有效 | 原样保留 | materialize |
| 签名有效但不是当前 canonical | 重写为 canonical marker | 仍允许 materialize，兼容在途旧上下文 |
| invalid MAC | 折叠为固定安全文本并审计 | 保留原 marker，返回稳定失败事件，不 materialize |
| cross session/workspace | 折叠并审计 scope mismatch | 保留原 marker，返回 scope mismatch |
| expired/tombstoned/unresolved | 折叠并审计对应状态 | 保留原 marker，返回对应稳定错误 |

上行无效 marker 不应发送给远程模型，也不应创建新 mapping。下行工具参数继续 fail-closed，APG 不决定 harness 是否执行工具。

### 5.4 Valid marker 的 canonical 收敛

为了兼容本次修改前已经存在于 Agent 上下文中的 marker：

- 旧 marker 只要 MAC、session、workspace 和 mapping 状态仍有效，就可被识别。
- 上行再次出现时，将其重写为 mapping 当前 canonical marker。
- 下行结构化工具参数中出现时，仍可 materialize，避免升级过程中破坏在途任务。
- mapping 到期或 policy 发生不兼容变化后，旧 marker 按稳定错误处理。

这样可以在不引入 `<APG:v2>` 的情况下逐步收敛到唯一表示。

### 5.5 Policy 与 signing key 轮换

需要明确以下行为：

- Policy hash 变化：推荐 tombstone 不兼容 mapping，产生新 handle；旧 marker 返回 `APG_PLACEHOLDER_POLICY_MISMATCH`。
- Signing key 变化：旧 marker 无法验证，按 invalid MAC 处理；运维文档必须说明重启恢复要求 signing secret 稳定。
- 普通 idle TTL 刷新：不得轮换 marker。
- GC/tombstone：必须清除 raw value，但保留足够的非敏感状态以返回稳定 tombstone 错误。

### 5.6 路径 alias 继续使用 canonical parent

保持当前 longest-active-parent 逻辑，并补充：

- canonical `/workspace/...` alias 再次进入请求时原样保留。
- 子路径优先使用最长有效父路径，避免错误父级。
- 父路径 mapping 过期后，子路径不得恢复到已过期 raw path。
- Windows、POSIX、隐藏文件、空格、句末标点和路径 suffix 分别测试。

### 5.7 安全审计

新增或统一以下安全事件，不记录完整 marker、handle、session 或 raw value：

- `canonical_placeholder_issued`
- `canonical_placeholder_reused`
- `placeholder_canonicalized`
- `placeholder_preserved`
- `placeholder_rejected`
- `path_parent_alias_reused`

事件只保留 kind、subtype、reason code、endpoint、request ID 和计数。

## 6. 实施阶段

### Phase 0：先建立失败基线

在修改实现前新增当前应失败的测试：

1. 同一 secret 间隔超过一秒再次 sanitize，完整 marker 必须相同。
2. 同一 PII 间隔超过一秒再次 sanitize，完整 marker 必须相同。
3. `sanitize(sanitize(x))` 不得改变结果。
4. 合法 marker 重新进入请求不得生成第二条 mapping。
5. invalid marker 重复扫描不得产生 marker nesting。
6. 一次工具失败后使用先前合法 marker 重试，仍可 materialize。
7. APG 重启后，同一 active mapping 生成相同 marker。

### Phase 1：SQLite 与 signer

1. 为 mapping schema 增加 `placeholder_issued_at`。
2. 启动迁移时检测列是否存在；旧行回填 `created_at`。
3. 扩展 `MappingRecord`。
4. 实现 `issue_for_record()`。
5. 替换所有直接 marker 签发调用。
6. 验证并发 upsert 只产生一个 canonical marker。

### Phase 2：请求 marker canonicalization

1. 在 `sanitize_text()` 通用 detector 前处理 marker span。
2. 合法 canonical marker 原样保留。
3. 合法旧 marker 收敛为 canonical marker。
4. 无效 marker 折叠且不创建 mapping。
5. 确保 detector 不再合并、扩展或覆盖已保护的 marker span。
6. 为 `sanitize_json()` 的任意嵌套字段复用同一逻辑。

### Phase 3：流式与协议统一

1. Chat、Anthropic 和 Responses 的 tool argument buffer 在 flush 时使用相同 validator。
2. visible text scanner 不得把 canonical marker 的片段包装为新 marker。
3. 对逐字符 marker、UTF-8 边界、CRLF 和多行 SSE 增加 canonicalization 测试。
4. 最终 snapshot/done 事件不得重新引入旧 marker 或 raw value。
5. EOF、客户端断开和 malformed JSON 必须保留稳定 audit termination。

### Phase 4：路径与重试稳定性

1. 固化 parent alias 加 suffix 的实现与测试。
2. 强制一次工具失败，再让同一上下文继续请求。
3. 验证错误消息中的 alias 和 marker 不发生身份漂移。
4. 验证两组交错 secret/PII 调用在失败重试后仍保持各自身份。
5. 验证 APG 重启后路径和 placeholder 都能恢复。

### Phase 5：文档与兼容性

1. 更新 README 中“stable placeholder”的精确定义。
2. 更新 design、threat model 和 harness contract。
3. 明确旧 marker 的兼容窗口与 policy/signing key 轮换行为。
4. 在 roadmap 中记录 referential stability 已完成，而不是只记录 signed placeholder 格式。

## 7. 测试计划

### 7.1 Mapping 与 signer 单元测试

- `test_placeholder_stable_across_wall_clock_seconds`
- `test_idle_refresh_does_not_rotate_placeholder`
- `test_concurrent_upsert_returns_one_marker`
- `test_placeholder_stable_after_store_restart`
- `test_tombstone_then_recreate_rotates_handle`
- `test_policy_change_rejects_old_marker`
- `test_signing_key_change_rejects_old_marker`

### 7.2 Request canonicalization 测试

- `test_valid_placeholder_request_roundtrip_is_idempotent`
- `test_valid_legacy_placeholder_converges_to_canonical`
- `test_invalid_placeholder_is_folded_without_mapping`
- `test_cross_session_placeholder_is_not_rewrapped`
- `test_expired_placeholder_is_not_rewrapped`
- `test_marker_adjacent_to_secret_and_path_keeps_exact_span`
- `test_nested_json_marker_handling_is_idempotent`

### 7.3 流式测试

- Chat/Anthropic/Responses 各覆盖单 marker、两个交错 marker 和逐字符分片。
- 先发送旧合法 marker，再在最终 snapshot 中发送 canonical marker。
- 先产生工具失败，再在下一轮复用旧 marker。
- invalid marker 必须产生一次稳定失败，不得被重新签发。
- 所有流要求 `parse_errors=0`，协议错误 fail-closed。

### 7.4 路径测试

- 父目录、子目录和文件共享一个 alias 根。
- 同 basename 不同 workspace 不碰撞。
- session/workspace 之间不共享 mapping。
- 重启后保持相同 alias。
- 标点、引号、Windows 路径和隐藏 credential 文件不破坏 suffix。

### 7.5 强制失败真实 Agent 测试

新增 `retry_materialization` live 场景：

1. Agent 读取包含 secret 和 PII 的两个本地文件。
2. 第一次 validator 调用由 fixture 有意返回安全的 `RETRY_ONCE`，不判断值错误。
3. 等待至少两秒，确保旧实现会产生不同时间戳。
4. Agent 在第二轮继续使用上下文中的 placeholder。
5. 第二次调用必须成功，且不得重新读取或猜测 marker。

再增加：

- 两个交错 validator 均先失败一次再成功。
- APG 在读取后、工具调用前重启的 deterministic mini-agent loop。
- 合法旧 marker、invalid MAC、cross-session、expired 和 tombstone 各自只有一次稳定错误。

Live runner 只负责构造失败和记录工具轨迹；工具权限仍属于 harness，不作为 APG 产品能力。

## 8. 数据迁移与发布

### 8.1 SQLite 迁移

- 使用 `PRAGMA table_info(mappings)` 检测 `placeholder_issued_at`。
- 缺失时执行 `ALTER TABLE`，随后用 `created_at` 回填。
- 在同一事务中完成迁移，失败则拒绝启动，避免部分迁移。
- 增加旧数据库 fixture 和并发启动测试。

### 8.2 兼容策略

- 保持 `<APG:v1:...>` 格式不变。
- 旧合法 marker 在 mapping 有效期内继续可 materialize。
- 上行旧 marker 自动收敛为 canonical marker。
- 不迁移 tombstoned raw value，不恢复已经清除的数据。

### 8.3 发布门槛

发布前必须同时满足：

- 全量 pytest 通过。
- 确定性 E2E `14/14` 通过。
- Chat、Anthropic、Responses 黑盒流探针通过。
- `retry_materialization` 在 Claude Code 和 OpenCode 均通过。
- upstream、audit、final、generated files 无 canary。
- final 和 generated files 无 APG marker。
- provider key 文件扫描无命中。
- `git diff --check` 通过。

## 9. 风险与取舍

### 9.1 Stable marker 是否增加重放风险

不会扩大当前实际授权窗口。旧实现签发过的 marker 本来就在 mapping TTL 内持续有效；只是远程模型每轮看到的字符串不同。canonical marker 将可见身份与真实有效期对齐，减少歧义而不延长 mapping 生命周期。

### 9.2 Policy 变化

如果 policy hash 变化后继续复用 marker，会使旧决策语义不明确。推荐将 policy 变化视为 identity rotation，并稳定返回 policy mismatch，而不是静默重新签发同一 handle。

### 9.3 旧上下文中存在多个合法 marker

升级后短期内可能同时存在多个历史 marker。上行 canonicalization 必须把它们收敛到一个 canonical marker；下行 materialization 在兼容窗口内仍接受签名有效且 mapping active 的旧 marker。

### 9.4 Marker 明文透传给远程模型

合法 placeholder 本来就是 APG 提供给远程模型的 opaque pseudonym。原样保留 canonical marker 不会暴露 raw value；审计和最终用户文本仍不得输出完整 marker。

## 10. 验收标准

实现完成后必须证明：

1. 同一 active mapping 跨秒、跨请求、跨协议和重启后完整 marker 字节相同。
2. 合法 marker 重复进入请求不会增加 mapping 数量，也不会形成嵌套 marker。
3. 工具失败后重试仍能使用原 marker materialize 成功。
4. 两个交错 handle 不串值、不串 session、不串 workspace。
5. invalid、expired、tombstone 和 cross-session marker 始终稳定 fail-closed。
6. 路径 alias 在父子层级、重启和并发情况下保持可组合。
7. 所有流无 parse error，最终 snapshot 不重新引入 raw value 或旧 marker。
8. APG 核心没有新增任何工具权限、命令审批或文件写入策略。

只有这些条件全部满足后，才能把“signed placeholder”升级为“referentially stable signed placeholder”，并把强制重试场景纳入正式 live acceptance。
