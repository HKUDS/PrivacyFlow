"use strict";

(() => {
  const STORAGE_KEY = "apg_locale";
  const exact = new Map([
    ["主导航", "Primary navigation"],
    ["界面语言", "Interface language"],
    ["概览", "Overview"],
    ["审计记录", "Audit"],
    ["上行替换与本地还原", "Upstream replacements and local materializations"],
    ["受保护值", "Protected values"],
    ["本地映射生命周期与撤销", "Local mapping lifecycle and revocation"],
    ["检测器配置", "Detectors"],
    ["按检测内容组织的本地模块流水线", "Local module pipeline organized by detection scope"],
    ["等待连接", "Waiting for connection"],
    ["本地网关已连接", "Local gateway connected"],
    ["连接已断开", "Disconnected"],
    ["退出管理面板", "Sign out"],
    ["隐私运行概览", "Privacy operations overview"],
    ["最近 24 小时的网关活动", "Gateway activity over the last 24 hours"],
    ["刷新当前页面", "Refresh current view"],
    ["APG 总开关", "APG master switch"],
    ["一键开启或关闭 APG 保护。", "Turn APG protection on or off with one click."],
    ["正在读取状态…", "Loading status..."],
    ["启用 APG 全局保护", "Enable APG global protection"],
    ["不可用", "Unavailable"],
    ["保护已开启", "Protection enabled"],
    ["旁路模式", "Bypass mode"],
    ["没有可用的检测配置，APG 全局保护暂时无法启用。", "No usable detector configuration is available, so APG global protection cannot be enabled."],
    ["请先选择并启用可用的上游配置。", "Select and activate a usable upstream configuration first."],
    ["未选择检测配置", "No detector configuration selected"],
    ["APG 全局保护已开启", "APG global protection enabled"],
    ["APG 已切换为旁路模式", "APG switched to bypass mode"],
    ["配置上游模型", "Configure upstream model"],
    ["未配置", "Not configured"],
    ["需要配置", "Setup required"],
    ["已配置", "Configured"],
    ["输入模型服务商的 API Key 后即可开始使用 Agent。密钥只保存在本机。", "Enter your model provider API key to start using agents. The key stays on this machine."],
    ["输入模型服务商的 Base URL 和 API Key 后即可开始使用 Agent。配置只保存在本机。", "Enter your model provider Base URL and API key to start using agents. The configuration stays on this machine."],
    ["上游凭据已生效。APG 不会通过管理接口回显已保存的密钥。", "The upstream credential is active. APG never returns the saved key through the management API."],
    ["上游连接配置已生效。APG 不会通过管理接口回显已保存的密钥。", "The upstream connection is active. APG never returns the saved key through the management API."],
    ["配置已在本机保存，密钥不会回显。", "Saved locally; keys are never displayed."],
    ["填写 Base URL 和 API Key。", "Enter a Base URL and API key."],
    ["更换 API Key", "Replace API key"],
    ["更换上游配置", "Change upstream configuration"],
    ["已保存配置", "Saved configurations"],
    ["暂无配置", "No saved configurations"],
    ["默认配置", "Default configuration"],
    ["启用所选", "Activate selected"],
    ["启用所选配置", "Activate selected configuration"],
    ["新增配置", "New configuration"],
    ["新增上游配置", "Add upstream configuration"],
    ["删除上游配置", "Delete upstream configuration"],
    ["编辑上游配置", "Edit upstream configuration"],
    ["配置名称", "Configuration name"],
    ["例如：Anthropic 生产环境", "For example: Anthropic production"],
    ["编辑时留空可保留现有密钥", "Leave blank while editing to keep the saved key"],
    ["上游 Base URL", "Upstream Base URL"],
    ["上游 API Key", "Upstream API key"],
    ["当前 Base URL", "Current Base URL"],
    ["上游协议", "Upstream protocol"],
    ["上游 API 格式", "Upstream API format"],
    ["待填写", "Not set"],
    ["待选择", "Not selected"],
    ["请选择协议", "Select protocol"],
    ["请选择格式", "Select format"],
    ["发送至", "Sent to"],
    ["取消", "Cancel"],
    ["保存并启用", "Save and enable"],
    ["请输入不含凭据、查询参数或片段的完整 HTTP(S) Base URL。", "Enter a complete HTTP(S) Base URL without embedded credentials, query parameters, or a fragment."],
    ["请输入上游 API Key。", "Enter the upstream API key."],
    ["请选择上游协议。", "Select the upstream protocol."],
    ["请选择上游 API 格式。", "Select the upstream API format."],
    ["上游连接配置已安全保存并启用", "Upstream connection saved securely and enabled"],
    ["上游连接配置已在当前进程中启用", "Upstream connection enabled for the current process"],
    ["Agent 接入", "Agent connection"],
    ["API 协议", "API protocol"],
    ["复制 Base URL", "Copy Base URL"],
    ["复制 OpenAI Base URL", "Copy OpenAI Base URL"],
    ["复制 Anthropic Base URL", "Copy Anthropic Base URL"],
    ["显示 API Key", "Show API key"],
    ["隐藏 API Key", "Hide API key"],
    ["复制 API Key", "Copy API key"],
    ["生成随机 API Key", "Generate random API key"],
    ["生成新的 API Key", "Generate a new API key"],
    ["当前 API Key 将立即失效，请更新所有 Agent 配置。", "The current API key will stop working immediately. Update every Agent configuration."],
    ["API Key 已重新生成", "API key regenerated"],
    ["复制", "Copy"],
    ["复制接入命令", "Copy connection command"],
    ["Agent 快捷接入", "Agent quick setup"],
    ["展开查看常见 Agent 的接入步骤和快捷复制", "Expand for setup steps and quick copy for common agents"],
    ["复制内容会包含当前本地 API Key，请只粘贴到可信的本机配置或终端。", "Copied content includes the current local API key. Paste it only into trusted local configuration or terminals."],
    ["复制 Claude Code 环境变量", "Copy Claude Code environment variables"],
    ["复制 OpenCode 配置", "Copy OpenCode configuration"],
    ["复制 Codex 配置", "Copy Codex configuration"],
    ["复制 Codex 密钥变量", "Copy Codex key variable"],
    ["查看 Claude Code 详细使用方法", "View detailed Claude Code setup"],
    ["查看 OpenCode 详细使用方法", "View detailed OpenCode setup"],
    ["查看 Codex 详细使用方法", "View detailed Codex setup"],
    ["详细使用方法", "Detailed setup"],
    ["Claude Code 详细使用方法", "Claude Code detailed setup"],
    ["OpenCode 详细使用方法", "OpenCode detailed setup"],
    ["Codex 详细使用方法", "Codex detailed setup"],
    ["复制环境变量，在终端粘贴后运行 Claude Code。", "Copy the environment variables, paste them into a terminal, then run Claude Code."],
    ["复制 JSON 并合并到 opencode.json，然后选择 APG 模型。", "Copy the JSON into opencode.json, then select the APG model."],
    ["将配置加入 ~/.codex/config.toml，再复制密钥变量后启动 Codex。", "Add the configuration to ~/.codex/config.toml, copy the key variable, then start Codex."],
    ["通过 APG 的 Anthropic Messages 接口运行 Claude Code。环境变量只影响当前终端会话。", "Run Claude Code through APG's Anthropic Messages endpoint. The environment variables apply only to the current terminal session."],
    ["通过 APG 的 OpenAI Chat Completions 接口运行 OpenCode。配置可以按用户全局保存，也可以只用于单个项目。", "Run OpenCode through APG's OpenAI Chat Completions endpoint. Save the configuration globally or only for one project."],
    ["通过 APG 的 OpenAI Responses 接口运行 Codex。Codex 配置与 API Key 分开保存。", "Run Codex through APG's OpenAI Responses endpoint. The Codex configuration and API key are stored separately."],
    ["准备 APG", "Prepare APG"],
    ["确认上游模型配置和 APG 总开关均已启用。", "Confirm that the upstream model configuration and APG master switch are enabled."],
    ["复制环境变量", "Copy environment variables"],
    ["点击 Claude Code 卡片上的复制按钮，将生成的全部环境变量粘贴到准备运行 Claude Code 的同一个终端。", "Click the copy button on the Claude Code card, then paste all generated environment variables into the same terminal where you will run Claude Code."],
    ["启动 Claude Code", "Start Claude Code"],
    ["在该终端进入项目目录，然后启动 Claude Code。", "In that terminal, enter the project directory and start Claude Code."],
    ["确认连接", "Verify the connection"],
    ["发送一条测试消息；请求应出现在 APG 的审计记录中。", "Send a test message. The request should appear in APG's audit log."],
    ["关闭终端后这些环境变量会失效；如需长期使用，可将它们保存到受信任的本机 Shell 配置中。", "These environment variables expire when the terminal closes. For persistent use, save them in a trusted local shell configuration."],
    ["复制配置", "Copy configuration"],
    ["点击 OpenCode 卡片上的复制按钮，复制完整 JSON 配置。", "Click the copy button on the OpenCode card to copy the complete JSON configuration."],
    ["写入配置文件", "Write the configuration file"],
    ["合并到全局配置 ~/.config/opencode/opencode.json，或项目根目录的 opencode.json；不要覆盖文件中已有的其他设置。", "Merge it into the global ~/.config/opencode/opencode.json or the project-root opencode.json. Do not overwrite other existing settings."],
    ["启动并选择模型", "Start and select the model"],
    ["在项目目录启动 OpenCode，并使用配置中的 APG 模型。", "Start OpenCode in the project directory and use the APG model from the configuration."],
    ["复制的配置包含当前本地 API Key，请不要提交到 Git 或粘贴到不受信任的位置。", "The copied configuration contains the current local API key. Do not commit it to Git or paste it into an untrusted location."],
    ["点击 Codex 卡片上的复制按钮，将 TOML 内容合并到 ~/.codex/config.toml。", "Click the copy button on the Codex card and merge the TOML content into ~/.codex/config.toml."],
    ["设置本地 API Key", "Set the local API key"],
    ["点击钥匙按钮复制密钥变量，然后粘贴到准备运行 Codex 的终端。", "Click the key button to copy the key variable, then paste it into the terminal where you will run Codex."],
    ["启动 Codex", "Start Codex"],
    ["在同一个终端进入项目目录，然后启动 Codex。", "In the same terminal, enter the project directory and start Codex."],
    ["密钥环境变量只影响当前终端会话。Codex 通过 env_key 读取它，密钥本身不会写入 config.toml。", "The key environment variable applies only to the current terminal session. Codex reads it through env_key, so the key itself is not written to config.toml."],
    ["拦截趋势", "Interception trend"],
    ["最近七天拦截数量", "Interceptions over the last seven days"],
    ["风险等级", "Risk levels"],
    ["最近拦截", "Recent interceptions"],
    ["查看全部", "View all"],
    ["查看全部审计记录", "View all audit records"],
    ["查看请求详情", "View request details"],
    ["查看事件详情", "View event details"],
    ["时间", "Time"],
    ["类型", "Type"],
    ["处理", "Action"],
    ["端点", "Endpoint"],
    ["状态", "Status"],
    ["网关状态", "Gateway status"],
    ["替换记录", "Replacement records"],
    ["还原记录", "Materialization records"],
    ["审计记录类型", "Audit record type"],
    ["搜索", "Search"],
    ["端点、请求编号、会话", "Endpoint, request ID, or session"],
    ["风险", "Risk"],
    ["全部风险", "All risks"],
    ["严重", "Critical"],
    ["高", "High"],
    ["中", "Medium"],
    ["低", "Low"],
    ["全部端点", "All endpoints"],
    ["显示敏感原文", "Show sensitive originals"],
    ["隐藏敏感原文", "Hide sensitive originals"],
    ["替换内容", "Replacement"],
    ["还原内容", "Materialization"],
    ["检测与动作", "Detection and action"],
    ["工具与结果", "Tool and result"],
    ["出现", "Occurrences"],
    ["次数", "Count"],
    ["上下文", "Context"],
    ["没有匹配记录", "No matching records"],
    ["调整筛选条件后再试。", "Adjust the filters and try again."],
    ["本地映射保留", "Local mapping retention"],
    ["永久保留", "Keep indefinitely"],
    ["空闲后自动清除", "Clear after inactivity"],
    ["关闭", "Off"],
    ["关闭弹窗", "Close"],
    ["开启", "On"],
    ["启用映射自动清除", "Enable automatic mapping clearing"],
    ["时长", "Duration"],
    ["单位", "Unit"],
    ["分钟", "minutes"],
    ["小时", "hours"],
    ["天", "days"],
    ["保存设置", "Save settings"],
    ["映射清单", "Mapping registry"],
    ["全部类型", "All types"],
    ["显示受保护值原文", "Show protected originals"],
    ["隐藏受保护值原文", "Hide protected originals"],
    ["清理过期记录", "Clear expired records"],
    ["撤销受保护值", "Revoke protected value"],
    ["标识", "Identifier"],
    ["原文", "Original"],
    ["分类", "Classification"],
    ["作用域", "Scope"],
    ["最后使用", "Last used"],
    ["到期时间", "Expires"],
    ["操作", "Action"],
    ["原值默认隐藏", "Original values are hidden by default"],
    ["仅在管理员确认后临时读取仍有效的本地原值；关闭显示后立即清除页面中的原文。", "Active local originals are read temporarily only after administrator confirmation. Hiding them immediately clears the page."],
    ["确认后临时显示，关闭显示即清除。", "Shown temporarily after confirmation and cleared when hidden."],
    ["启用配置", "Activate"],
    ["配置名称", "Configuration name"],
    ["配置说明", "Configuration description"],
    ["总流程超时（ms）", "Pipeline timeout (ms)"],
    ["APG 内置安全防线", "APG built-in safety guard"],
    ["删除", "Delete"],
    ["保存配置", "Save configuration"],
    ["检测模块", "Detector modules"],
    ["检测器试跑", "Detector dry run"],
    ["运行检测", "Run detection"],
    ["测试文本", "Test text"],
    ["输入一段本地测试文本", "Enter local test text"],
    ["等待测试", "Waiting to test"],
    ["连接本地隐私网关", "Connect to the local privacy gateway"],
    ["管理员 API Key", "Administrator API key"],
    ["连接", "Connect"],
    ["密钥仅保存在当前浏览器会话中。", "The key is stored only for this browser session."],
    ["详情", "Details"],
    ["新建检测器配置", "Create detector configuration"],
    ["基于", "Based on"],
    ["创建配置", "Create configuration"],
    ["编辑检测模块", "Edit detector module"],
    ["新增检测模块", "Add detector module"],
    ["模块名称", "Module name"],
    ["模块类型", "Module type"],
    ["正则检测", "Regex detection"],
    ["熵值检测", "Entropy detection"],
    ["路径检测", "Path detection"],
    ["本地小模型", "Local model"],
    ["部署模块", "Deployment module"],
    ["高级设置", "Advanced settings"],
    ["模块超时（ms）", "Module timeout (ms)"],
    ["不限制", "No limit"],
    ["失败策略", "Failure mode"],
    ["失败时跳过模块（Fail open）", "Skip module on failure (Fail open)"],
    ["失败时中止流程（Fail closed）", "Stop pipeline on failure (Fail closed)"],
    ["应用到草稿", "Apply to draft"],
    ["确认操作", "Confirm action"],
    ["确认", "Confirm"],
    ["请求", "Requests"],
    ["拦截", "Interceptions"],
    ["本地还原", "Local materializations"],
    ["活跃受保护值", "Active protected values"],
    ["最近 24 小时", "Last 24 hours"],
    ["敏感内容已替换或折叠", "Sensitive content replaced or folded"],
    ["已替换或折叠", "Replaced or folded"],
    ["仅结构化工具参数", "Structured tool arguments only"],
    ["保存在本地映射库", "Stored in the local mapping registry"],
    ["本地保存", "Stored locally"],
    ["检测配置", "Detector configuration"],
    ["工作区", "Workspace"],
    ["上游", "Upstream"],
    ["严格模式", "Strict"],
    ["开启", "On"],
    ["关闭", "Off"],
    ["管理面板", "Control plane"],
    ["仅本机", "Local only"],
    ["远程绑定", "Remote bind"],
    ["未指定上游", "No upstream specified"],
    ["请输入上游 API Key。", "Enter an upstream API key."],
    ["上游 API Key 已安全保存并启用", "Upstream API key saved securely and enabled"],
    ["上游 API Key 已在当前进程中启用", "Upstream API key enabled for the current process"],
    ["保存失败。", "Save failed."],
    ["未配置本地 API Key", "No local API key configured"],
    ["API Key 已复制", "API key copied"],
    ["Base URL 已复制", "Base URL copied"],
    ["Claude Code 接入命令已复制", "Claude Code connection command copied"],
    ["Claude Code 环境变量已复制", "Claude Code environment variables copied"],
    ["OpenCode 配置已复制", "OpenCode configuration copied"],
    ["Codex 配置已复制", "Codex configuration copied"],
    ["Codex 密钥变量已复制", "Codex key variable copied"],
    ["接入配置已复制", "Connection configuration copied"],
    ["请求失败", "Request failed"],
    ["暂无替换记录", "No replacement records"],
    ["暂无还原记录", "No materialization records"],
    ["原文已清除", "Original cleared"],
    ["替换为", "Replaced with"],
    ["还原为", "Materialized as"],
    ["替换", "Replacement"],
    ["本地工具", "Local tool"],
    ["未还原", "Not materialized"],
    ["已还原", "Materialized"],
    ["暂无匹配请求", "No matching requests"],
    ["无", "None"],
    ["正在读取安全审计详情…", "Loading safe audit details..."],
    ["会话", "Session"],
    ["临时显示", "Temporarily shown"],
    ["已隐藏", "Hidden"],
    ["无逐项详情", "No operation details"],
    ["该请求来自旧版安全审计，只保留了汇总记录。", "This request comes from a legacy audit record that contains summary data only."],
    ["上行替换", "Upstream replacements"],
    ["本次请求没有上行替换。", "This request has no upstream replacements."],
    ["本次请求没有本地还原。", "This request has no local materializations."],
    ["未还原与协议错误", "Materialization and protocol failures"],
    ["原文只从当前仍有效的本地映射临时读取。请确认屏幕与浏览器环境可信。", "Originals are read temporarily from active local mappings only. Confirm that the screen and browser environment are trusted."],
    ["暂无记录", "No records"],
    ["阶段", "Phase"],
    ["该事件没有检测项。", "This event has no detections."],
    ["当前清单", "Current registry"],
    ["活跃", "Active"],
    ["不自动过期", "No automatic expiry"],
    ["撤销", "Revoke"],
    ["没有受保护值记录", "No protected-value records"],
    ["撤销受保护值", "Revoke protected value"],
    ["显示受保护值原文", "Show protected originals"],
    ["原文只会从当前仍有效的本地映射临时读取。请确认屏幕与浏览器环境可信。", "Originals are read temporarily from active local mappings only. Confirm that the screen and browser environment are trusted."],
    ["请输入有效的自动清除时长", "Enter a valid automatic-clearing duration"],
    ["自动清除时长须在 1 分钟到 365 天之间", "Automatic clearing must be between 1 minute and 365 days"],
    ["已关闭自动清除", "Automatic clearing disabled"],
    ["受保护值已撤销", "Protected value revoked"],
    ["内置与部署模板", "Built-in and deployment templates"],
    ["用户配置", "User configurations"],
    ["放弃未保存更改", "Discard unsaved changes"],
    ["切换配置将丢弃当前草稿。", "Switching configurations will discard the current draft."],
    ["当前启用", "Active"],
    ["默认预设不可编辑，请复制或新建自定义配置。模块开关仍可直接调整。", "Default presets cannot be edited. Duplicate one or create a custom configuration; module switches remain adjustable."],
    ["当前配置", "Current configuration"],
    ["复制并编辑", "Copy and edit"],
    ["配置中还没有检测模块", "This configuration has no detector modules"],
    ["新增模块后，它们会按这里的顺序依次执行。", "Added modules run in the order shown here."],
    ["上移", "Move up"],
    ["下移", "Move down"],
    ["编辑", "Edit"],
    ["启用", "Enable"],
    ["检测器配置已保存并校验", "Detector configuration saved and validated"],
    ["请先保存当前草稿", "Save the current draft first"],
    ["检测器配置已启用", "Detector configuration activated"],
    ["删除检测器配置", "Delete detector configuration"],
    ["检测器配置已删除", "Detector configuration deleted"],
    ["空白配置", "Blank configuration"],
    ["新检测配置", "New detector configuration"],
    ["检测器配置已创建", "Detector configuration created"],
    ["已创建可编辑副本", "Editable copy created"],
    ["副本", "copy"],
    ["删除检测模块", "Delete detector module"],
    ["新检测模块", "New detector module"],
    ["最小 Token 长度", "Minimum token length"],
    ["熵阈值", "Entropy threshold"],
    ["Shell 配置目录", "Shell configuration directories"],
    ["Windows User 路径", "Windows user paths"],
    ["排除模式（逗号分隔 glob）", "Exclude patterns (comma-separated globs)"],
    ["模块风险等级（仅用于审计）", "Module risk level (audit only)"],
    ["运行方式", "Adapter"],
    ["模型分数阈值", "Model score threshold"],
    ["Hugging Face 模型地址或本地路径", "Hugging Face model ID or local path"],
    ["设备", "Device"],
    ["实体标签（逗号分隔）", "Entity labels (comma-separated)"],
    ["聚合方式", "Aggregation strategy"],
    ["模型按需延迟加载；是否允许下载由部署策略决定。", "Models load lazily. Deployment policy controls whether downloads are allowed."],
    ["规则名称", "Rule name"],
    ["正则表达式", "Regular expression"],
    ["数据类型", "Data type"],
    ["风险等级（仅用于审计）", "Risk level (audit only)"],
    ["动作", "Action"],
    ["Flags（逗号分隔）", "Flags (comma-separated)"],
    ["高级选项（选填）", "Advanced options (optional)"],
    ["Validators（选填）", "Validators (optional)"],
    ["必须通过的 Validators（选填）", "Required validators (optional)"],
    ["拒绝的 Validators（选填）", "Rejected validators (optional)"],
    ["请输入模块名称", "Enter a module name"],
    ["请输入测试文本", "Enter test text"],
    ["请先保存配置草稿再试跑", "Save the configuration draft before running a dry run"],
    ["正在检测…", "Detecting..."],
    ["未发现敏感内容", "No sensitive content found"],
    ["本地检测 · 未上传云端", "Local detection · Nothing uploaded"],
    ["已完成", "Completed"],
    ["进行中", "In progress"],
    ["已记录", "Recorded"],
    ["异常", "Error"],
    ["协议错误", "Protocol error"],
    ["连接中断", "Connection interrupted"],
    ["映射有效", "Mapping active"],
    ["原文已过期清除", "Original cleared after expiry"],
    ["原文已撤销清除", "Original cleared after revocation"],
    ["原文不可用", "Original unavailable"],
    ["已过期", "Expired"],
    ["已撤销", "Revoked"],
    ["凭据与密钥", "Credentials and keys"],
    ["凭据与密钥 - 自定义", "Credentials and keys - Custom"],
    ["个人信息", "Personal information"],
    ["本地开发环境", "Local development environment"],
    ["全面保护", "Comprehensive protection"],
    ["全面保护 - 自定义", "Comprehensive protection - Custom"],
    ["迁移的检测配置", "Migrated detector configuration"],
    ["由旧版检测器预设和覆盖项自动迁移", "Automatically migrated from legacy detector presets and overrides"],
    ["API key、密码、Token、私钥和数据库凭据", "API keys, passwords, tokens, private keys, and database credentials"],
    ["联系方式、身份与财务类个人信息", "Contact, identity, and financial personal information"],
    ["本机路径、配置目录和凭据文件位置", "Local paths, configuration directories, and credential-file locations"],
    ["凭据、个人信息与本地开发环境", "Credentials, personal information, and local development context"],
    ["凭据与密钥规则", "Credential and key rules"],
    ["个人信息规则", "Personal-information rules"],
    ["个人信息小模型", "Personal-information local model"],
    ["本地路径", "Local paths"],
    ["高熵 Token", "High-entropy token"],
    ["正则", "Regex"],
    ["路径", "Path"],
    ["熵值", "Entropy"],
    ["本地", "Local"],
    ["新建检测器配置", "Create detector configuration"],
    ["复制检测器配置", "Duplicate detector configuration"],
    ["复制并编辑检测器配置", "Duplicate and edit detector configuration"],
    ["启用检测器配置", "Activate detector configuration"],
    ["当前检测器配置", "Current detector configuration"],
    ["删除检测器配置", "Delete detector configuration"],
    ["新增检测模块", "Add detector module"],
    ["上移模块", "Move module up"],
    ["下移模块", "Move module down"],
    ["拖动排序", "Drag to reorder"],
    ["编辑模块", "Edit module"],
    ["复制模块", "Duplicate module"],
    ["删除模块", "Delete module"],
    ["添加正则规则", "Add regex rule"],
    ["删除正则规则", "Delete regex rule"],
    ["替换为", "Replace with"],
    ["还原为", "Materialize as"],
    ["多条安全正则与格式验证器", "Safe regular expressions and format validators"],
    ["本地路径位置", "Local path locations"],
  ]);

  const patterns = [
    [/^(\d[\d,]*) 条替换记录(?: · (\d[\d,]*) 次出现)?$/, (_, count, occurrences) => `${count} replacement records${occurrences ? ` · ${occurrences} occurrences` : ""}`],
    [/^(\d[\d,]*) 条还原记录(?: · (\d[\d,]*) 次出现)?$/, (_, count, occurrences) => `${count} materialization records${occurrences ? ` · ${occurrences} occurrences` : ""}`],
    [/^当前显示最近 (\d[\d,]*) 条$/, (_, count) => `Showing the latest ${count}`],
    [/^(\d[\d,]*) 未还原$/, (_, count) => `${count} not materialized`],
    [/^(\d[\d,]*) 次$/, (_, count) => `${count} times`],
    [/^(\d[\d,]*) 项$/, (_, count) => `${count} items`],
    [/^(\d[\d,]*) 条规则$/, (_, count) => `${count} rules`],
    [/^(\d[\d,]*) 个步骤$/, (_, count) => `${count} steps`],
    [/^(\d[\d,]*) 命中$/, (_, count) => `${count} findings`],
    [/^另有 (\d[\d,]*) 项操作仅计入总数。$/, (_, count) => `${count} additional operations are included in totals only.`],
    [/^工具 (.+)$/, (_, name) => `Tool ${name}`],
    [/^空闲 (.+)后清除$/, (_, duration) => `Clear after ${duration} idle`],
    [/^已启用：空闲 (.+)后清除$/, (_, duration) => `Enabled: clear after ${duration} idle`],
    [/^已清理 (\d[\d,]*) 条过期记录$/, (_, count) => `Cleared ${count} expired records`],
    [/^当前检测配置：(.+)$/, (_, name) => `Active detector configuration: ${translateCore(name)}`],
    [/^(.+)（当前）$/, (_, name) => `${translateCore(name)} (Active)`],
    [/^(.+) 将立即失效，之后的占位符无法还原。$/, (_, name) => `${name} will be revoked immediately and its placeholders can no longer be materialized.`],
    [/^(.+) 将被永久删除。$/, (_, name) => `${name} will be permanently deleted.`],
    [/^(.+) 将从配置草稿中移除。$/, (_, name) => `${name} will be removed from the configuration draft.`],
    [/^上移 (.+)$/, (_, name) => `Move ${translateCore(name)} up`],
    [/^下移 (.+)$/, (_, name) => `Move ${translateCore(name)} down`],
    [/^拖动排序 (.+)$/, (_, name) => `Drag to reorder ${translateCore(name)}`],
    [/^删除正则规则 (.+)$/, (_, name) => `Delete regex rule ${translateCore(name)}`],
    [/^编辑 (.+)$/, (_, name) => `Edit ${translateCore(name)}`],
    [/^复制 (.+)$/, (_, name) => `Duplicate ${translateCore(name)}`],
    [/^删除 (.+)$/, (_, name) => `Delete ${translateCore(name)}`],
    [/^(.+) - 自定义$/, (_, name) => `${translateCore(name)} - Custom`],
    [/^撤销受保护值 (.+)$/, (_, name) => `Revoke protected value ${translateCore(name)}`],
    [/^启用 (.+)$/, (_, name) => `Enable ${translateCore(name)}`],
    [/^(.+) · 当前$/, (_, name) => `${translateCore(name)} · Active`],
    [/^(正则检测|熵值检测|路径检测|本地小模型|部署模块) · (.+)$/, (_, type, id) => `${translateCore(type)} · ${id}`],
    [/^发现 (\d[\d,]*) 处敏感内容$/, (_, count) => `${count} sensitive findings`],
    [/^(.+)风险$/, (_, label) => `${translateCore(label)} risk`],
    [/^(.+)动作$/, (_, label) => `${translateCore(label)} action`],
  ];

  const textSources = new WeakMap();
  const attributeSources = new WeakMap();
  let translating = false;
  let locale = readLocale();

  function readLocale() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "zh" || saved === "en") return saved;
    } catch (_) {}
    return navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";
  }

  function translateCore(value) {
    if (exact.has(value)) return exact.get(value);
    for (const [pattern, replacer] of patterns) {
      if (pattern.test(value)) return value.replace(pattern, replacer);
    }
    return value;
  }

  function translateText(value) {
    const match = String(value).match(/^(\s*)([\s\S]*?)(\s*)$/);
    if (!match || !match[2]) return value;
    return `${match[1]}${translateCore(match[2])}${match[3]}`;
  }

  function sourceAttributes(element) {
    let sources = attributeSources.get(element);
    if (!sources) {
      sources = new Map();
      attributeSources.set(element, sources);
    }
    return sources;
  }

  function applyTextNode(node, restore = false) {
    const current = node.nodeValue || "";
    if (locale === "en") {
      const previous = textSources.get(node);
      if (previous === undefined || current !== translateText(previous)) textSources.set(node, current);
      const translated = translateText(textSources.get(node));
      if (current !== translated) node.nodeValue = translated;
    } else {
      const previous = textSources.get(node);
      if (restore && previous !== undefined) {
        if (current !== previous) node.nodeValue = previous;
      } else {
        textSources.set(node, current);
      }
    }
  }

  function applyElement(element, restore = false) {
    for (const name of ["aria-label", "title", "placeholder"]) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name) || "";
      const sources = sourceAttributes(element);
      if (locale === "en") {
        const previous = sources.get(name);
        if (previous === undefined || current !== translateText(previous)) sources.set(name, current);
        const translated = translateText(sources.get(name));
        if (current !== translated) element.setAttribute(name, translated);
      } else {
        const previous = sources.get(name);
        if (restore && previous !== undefined) {
          if (current !== previous) element.setAttribute(name, previous);
        } else {
          sources.set(name, current);
        }
      }
    }
  }

  function apply(root = document, restore = true) {
    translating = true;
    try {
      if (root.nodeType === Node.TEXT_NODE) applyTextNode(root, restore);
      if (root.nodeType === Node.ELEMENT_NODE) applyElement(root, restore);
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        if (node.nodeType === Node.TEXT_NODE) applyTextNode(node, restore);
        else applyElement(node, restore);
      }
      document.documentElement.lang = locale === "zh" ? "zh-CN" : "en";
      document.querySelectorAll("[data-locale]").forEach((button) => {
        const active = button.dataset.locale === locale;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });
    } finally {
      translating = false;
    }
  }

  function setLocale(next) {
    if (!["zh", "en"].includes(next) || next === locale) return;
    locale = next;
    try { localStorage.setItem(STORAGE_KEY, locale); } catch (_) {}
    apply(document);
    window.dispatchEvent(new CustomEvent("apg:localechange", {detail: {locale}}));
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.addEventListener("click", (event) => {
      const button = event.target.closest("[data-locale]");
      if (button) setLocale(button.dataset.locale);
    });
    apply(document);
    const observer = new MutationObserver((mutations) => {
      if (translating) return;
      for (const mutation of mutations) {
        if (mutation.type === "characterData") applyTextNode(mutation.target, false);
        else if (mutation.type === "attributes") applyElement(mutation.target, false);
        else mutation.addedNodes.forEach((node) => apply(node, false));
      }
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["aria-label", "title", "placeholder"],
    });
  });

  window.APG_I18N = {
    apply,
    get locale() { return locale; },
    setLocale,
    translate: (value) => locale === "en" ? translateText(value) : value,
  };
})();
