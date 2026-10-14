package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// goalsDefaultTmpl is the built-in EDITABLE body (段 [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `你是代码安全审计平台（SCA Audit）的目标分解器。你的职责是从用户输入中识别出**最终要交付、可核验的审计结果**，而不是规划审计步骤。

**第一步（拆分目标之前先做）：抽取操作约束**
从「任务目标 / 任务描述」里识别操作员对【可以做什么、不可以做什么操作】的明确规定，调用 set_constraints 逐条登记（如果描述、目标中不涉及操作约束可以不进行提取操作约束）：
- type=deny：禁止的操作（如「不改动被测源码」「不审计第三方依赖与前端」「不看测试代码」）。
- type=allow：明确允许/限定的审计范围（如「只审计 src/main/java 下的 Controller 与 Service」「只做接口与权限梳理」「只做静态分析」）。
- 约束 ≠ 目标，也 ≠ 审计步骤：它是对审计行为边界的规定。
- **约束必须【自包含、写死具体对象】**：把「当前目标/本模块/本仓库/本站/这个接口」这类**指代词**替换成任务目标/描述里的**具体值**。约束会被单独注入到执行阶段的提示里，脱离上下文后指代词无法判断指谁。
  例：目标是审计 order-service 仓库 → 写「只审计 order-service 的源码」而不是「只审计当前目标」；「只看 order-service 的接口层与权限校验」而不是「只看当前模块」。若原文只说「当前仓库」但仓库名已明确，就把仓库名填进去。
- **只登记目标/描述里【明确写出或强调】的约束，严禁臆造**；拿不准类型时用 deny（更保守）。
- 若目标/描述里确实没有任何操作约束，则**不要**调用 set_constraints。
登记完约束（如有）后，再进行下面的目标拆分。

**本平台的产物语义（用于读懂目标措辞）**：资产 = 代码里能暴露出来的东西，最重要的是**接口**（并判定该接口**所需权限**）；发现 = **代码级漏洞**，证据必须是源码位置 + 代码片段（不是运行时现象）。目标里出现「接口 / 权限 / 漏洞 / 代码缺陷」，都按这个语义理解。

**目标 = 最终可交付/可核验的审计结果**

**不是目标的内容（禁止列为子目标）**：
- 摸清源码树、清点入口与接口
- 逐文件代码走查、数据流追踪、权限判定的过程
- 漏洞的分析、确认与复现过程
- 结论复核、证据核对步骤

**拆分原则**：
- 用户描述的最终目标只有一个 → 输出一个
- 存在多个**相互独立**的最终交付物（如「全量接口与权限清单」与「高危漏洞确认清单」）→ 分别列出
- 能对应明确漏洞类的标注 vulnclass（如 sql-injection / xss / ssrf / deserialization / path-traversal / unauthorized-access / hardcoded-secret / weak-crypto）；接口清单、覆盖度类目标留空
- 严禁臆造用户未提及的目标

调用 set_goals 提交结果。`

// goalsScopeTail 是拼在可编辑正文之后、由代码持有的尾部：仅当【资产库 + 任务上下文】
// 都存在时才追加。它教拆解器把目标/描述里明确给出的【审计范围（代码仓库/模块）】也登记
// 下来（add_task_scope）。放代码里而不放进 DB 可编辑正文，是为了在已发布的库上始终生效、
// 无法被编辑掉——与 trafficTool 尾部同一套做法。
const goalsScopeTail = `

**额外职责：登记审计范围（代码仓库/模块）**
除拆分目标外，你还要从「任务目标 / 任务描述」里识别出**明确给出的审计范围**，调用 add_task_scope 登记（本任务的审计边界，也是资产测试覆盖度的分母）。**最小范围原则：只登记用户明确点到的那一个代码库/模块，绝不擅自放大。**
- 目标是具体仓库、模块或包路径（如 order-service、com.acme.order、src/main/java/com/acme/order、internal/payment）→ 取用户给出的那一级，kind=subdomain，value=仓库/模块/包路径。
  例：目标「审计 shop-web 的 user 模块」→ kind=subdomain，value=shop-web/user（**不是**整个 shop-web）。
  **严禁**把明确的子模块缩成整个代码库——看到某个模块就登记整个仓库会把范围扩到用户目标之外，违背最小范围原则。
- 仅当用户给的就是**整个代码库/整个项目、且不含任何子模块限定**（如直接写「审计 shop-web 全部源码」「整个仓库」）→ 才用 kind=root_domain，value=仓库/项目名。
- 若描述里还给部署地址、内网 IP 或网段 → 照旧用 kind=subdomain / root_domain / ip / cidr 登记对应值（覆盖度按接口所属 host 匹配，这类范围更容易对上资产）。
- kind 一律沿用原有取值（subdomain=精确到一个仓库/模块，root_domain=整个代码库，ip/cidr=IP 或网段），**不要发明新的 kind 值**。
- **不要**登记公司范围（company）——任务刚建立、资产系统里通常还没有这家公司，登记不上，公司级范围交由后续 plan 阶段处理。
其它规则：
- 只登记**目标/描述里明确写出**的范围；严禁臆造或推断未提及的仓库/模块/路径。
- 本任务的源码已解压在任务目录的 source/ 子目录下；范围取自这里实际存在的代码，别登记没有上传的仓库。
- reason 简述依据来自哪句话，便于审计。
- 若目标/描述中没有任何明确范围，则**不要**调用 add_task_scope。
先用 add_task_scope 登记范围（如有），再调用 set_goals 提交目标。`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a code-audit task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// prov is supplied by the caller (rather than built here from a Config) so goal
// decomposition rides the SAME provider instance as the rest of the engine — it
// shares the rate limiter, gets recorded by llmrec, and participates in LLM
// failover instead of quietly bypassing all three.
//
// desc is the task's free-text description (背景：审计范围/重点模块/交付要求等).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
//
// as + taskID 非空/为正时接上 add_task_scope：让拆解器能把它从目标/描述里抽出的
// 审计范围（代码仓库/模块）当场登记进本任务的 scope。
//
// ts is the task's exploration store: set_goals writes the decomposed goal nodes
// straight into it (the same managed tool the main agent uses to add goals at
// runtime). The returned specs are read back from the store so callers can emit
// per-goal activity and detect the "LLM produced nothing" case for their fallback.
func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

// DecomposeGoalsWithProvider is the task-runtime variant used when a task has an
// ordered provider chain. It preserves the same tools and write behavior while
// letting the caller own provider selection/failover. maxTokens is the profile's
// per-reply output cap (0 = send none).
func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	// 目标拆解是一次性调用：不挂 transcript store，所以 agentcore 不会往 ctx 上挂
	// session id（它只在有 writer 时才挂，见 agentcore.Prompt）。而按 session-id 头
	// 做提示缓存/粘性路由的网关（opencode zen 缺 x-opencode-session 直接 400
	// MissingSessionID）读的就是 ctx 上这个值——不补就是「对话正常、拆解 400」。
	// 显式挂一个稳定 id：同一探索的拆解请求共享它（利于命中缓存），且命名与
	// planner/worker 不冲突，能被 llmrec.parseSession 正确归因。
	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}
	// worker="goals" tags the goal nodes' provenance; ts/taskID let set_goals link
	// each goal under the task root. This is the catalog's real set_goals tool, so a
	// web-edited description/schema on it applies here too.
	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})
	// set_constraints 始终可用(不依赖 asset store):正文已含「先抽操作约束再拆目标」这步
	// (可在 agent 编辑页改措辞),这里只需接上工具。
	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}
	// Wire add_task_scope only when we have a real asset store + task to write to.
	// The scope-extraction tail is appended in lockstep so the prompt never asks for
	// a tool that isn't present.
	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "任务目标：\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\n任务描述（背景信息，可能含审计范围/重点模块/交付要求；仅供参考，不要臆造其中未提及的内容）：\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		// 3 步(抽约束 → 登记范围 → 拆目标)各需一次工具调用,给足回合避免收尾前漏调 set_goals。
		MaxTurns:     8,
		NonStreaming: nonStreaming, // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    maxTokens,    // 0 = 不发上限,由服务端默认值决定
	}, userMsg, captureEmit)
	// set_goals persisted the goals directly; read them back so the caller sees what
	// was written (empty slice ⇒ the LLM produced nothing ⇒ caller falls back).
	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
