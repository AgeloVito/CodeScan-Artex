package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const findingIDGuidance = "\n\n**漏洞编号约定**：finding_id 是独立漏洞记录 ID；finding_node_id 是探索节点 ID。list_findings / list_task_findings / node_detail / get_task_node_detail 的 id 保留为探索节点 ID，应从同一返回的 finding_id 读取独立编号。get_finding_traffic / bind_finding_traffic 用独立 finding_id。旧 update_finding_report 的 finding_id 参数仍传 finding_node_id。不要把 report_finding 第一行的数字用于证据工具，也不要遇到编号错误后猜测其他数字。"

// retestPacketGuidance 是「推演复测报文」的生成规约。
//
// 平台不出网、不抓包，漏洞详情页的「原始数据包」在没有真实流量证据时由模型推演。
// 这里必须把边界讲清楚：它是复测用例而非证据，取值必须有源码依据，凭证只能是占位符，
// 且**不允许为了生成报文去真正发起请求或编译运行代码**（否则模型会试图「造证据」）。
const retestPacketGuidance = "\n\n**复测报文（可选，非证据）**：平台不抓包，漏洞详情页的「原始数据包」引用你在 report_finding 的 retest_packets 里推演的复测用例。\n" +
	"★**按接口逐份提交**：报文里写死了 Host、路径与参数，一份报文只可能对应一个接口。所以 asset_ids 里有几个接口，就交几份报文，每份用 asset_id 声明它属于哪个接口；**不要只写一份代表全部**——详情页会按接口列槽位，一份报文压在一串资产下面会让复测打错目标。\n" +
	"每份报文的要求：raw_request 必须是完整、可直接粘贴的 HTTP/1.1 报文（起始行 + Host 等头部 + 空行 + 正文），路径与参数必须与 asset_id 指向的那个接口一致（该接口的 params 见 list_assets 返回），正文格式与 Content-Type 匹配。取值只能来自你实际读过的源码或配置：每条取值在 grounded_refs 用「文件:行号」给出依据，无法从源码确定的值（会话凭证、运行时生成的 ID 等）写进 assumptions 并说明假设。Cookie / Authorization 等凭证一律写 <占位符>，绝不能编造看起来真实的凭证；也不要为了生成报文去真正发起请求、连接目标或编译运行代码。\n" +
	"**给不出的接口就不给**：只为你确实读过其源码、能说清参数依据的接口写报文，剩下的留空（页面会显示「未生成」），不要为了凑数复制另一个接口的正文——参数对不上接口的报文比没有报文更坏。推演报文只是复测用例，不能替代证据：漏洞结论仍必须由源码与静态分析结论支撑，evidence 照常填写。非 HTTP 漏洞（配置、依赖、加密等）省略该参数。服务端会逐份解析校验，未通过时仍会保存但标记为不可信。"

// retestPacketGuidanceFor 只在工具面里确实有 report_finding 时给出报文规约。
func retestPacketGuidanceFor(tools []actool.CoreTool) string {
	for _, tool := range tools {
		if tool.Name() == "report_finding" {
			return retestPacketGuidance
		}
	}
	return ""
}

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	// 代码审计平台不出网、不抓包：traffic_* / bind_finding_traffic 工具已从所有 agent
	// 的工具面移除，流量交接说明也会误导模型去调用不存在的工具。所以这里恒定 false——
	// 走的是「关闭」分支（剔除 bind_finding_traffic、剥掉 schema 里的流量参数），
	// 与 settingAgentTrafficBinding 的历史取值无关。
	return false
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, retestPacketGuidanceFor(out)
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\n默认由报告 Agent 在编写报告前核对并绑定流量。上报者在 evidence 中保留验证命令、关键输出、已有的真实流量 ID 及其用途，供报告 Agent 对照执行记录核实；无需为绑定额外查包。兼容显式即时绑定：traffic_refs 或 evidence_hint_id 可提交已核实的引用，后者读取本任务指定 hint 的结构化引用；任一无效则本次上报全部失败。TCP/无包不需要这些可选参数。返回 finding_id 与 finding_node_id 分别表示独立记录和探索节点。"
		case "add_hint", "add_task_hint":
			note = "\n交接已确认漏洞时，在对应提示的 traffic_refs 中保留已核实流量的 ID、用途、说明和顺序（单条放顶层，批量放对应 hints 元素），并在 text 中说明它证明的具体漏洞。调用方不能只交接文字而丢弃已有流量引用。未核实的候选不能作为证据传递。"
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**流量证据交接（可选）**：自动绑定默认由报告 Agent 在漏洞入库后、编写报告前完成。上报者应在 evidence 保留验证命令、关键输出、已有真实流量 ID 及其用途，任务中带 intent_id，便于报告 Agent 追溯；不必为了绑定额外查包。Auto / Planner 代为上报时不要丢弃执行者已有的引用。add_hint / add_task_hint 可用 traffic_refs 交接；显式即时绑定仍兼容 report_finding 的 traffic_refs / evidence_hint_id。TCP 或无包时正常登记，不能猜测 ID，也不能仅为补包重复探测。"
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\n平台对话没有任务上下文时，不直接调用 report_finding；通过 add_task_hint 向已有对应任务交接，由任务 Agent 登记，并用 list_task_findings 核对结果。"
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\n判定目标完成前，先完成本次已有证据的上报/交接。不要在证据交接尚未完成时仅因文字漏洞已登记就结束任务、取消 Worker；无包不要求等待或强行抓包。"
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**报告前自动关联流量（已开启）**：你负责为本次触发的漏洞核对并绑定流量，再撰写报告。先从 report_finding 返回 JSON 或 get_task_node_detail / list_task_findings 取得明确的 finding_id 与 finding_node_id。读取漏洞详情、对应意图的执行记录及已有证据清单，优先使用上报者交接的真实 ID。若本次验证为 HTTP 且流量工具可用，用 traffic_search 筛选候选，再用 traffic_get 逐条核实请求/响应确实支持该漏洞；域名和时间只用于筛选，不证明归属。将确认的证据按复现顺序用 bind_finding_traffic(finding_id, traffic_refs) 关联，选择 baseline / proof / verification / supporting 并说明用途。只能操作本次漏洞，不重复创建漏洞或重新探测目标。绑定成功后重新调用 get_finding_traffic 获取最新 version，读取所需正文，再将实际读取的 version 作为 evidence_version 传给 update_finding_report（其 finding_id 参数仍用 finding_node_id）。已有绑定不必重复追加。TCP、未采集、工具不可用或没有确切匹配时，跳过自动绑定，依据文字/命令证据正常写报告并说明原因，不得为凑齐流量而猜测。绑定失败不宣称成功；保留已有证据并在报告说明未绑定原因。"
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "可选：已核实且对应本提示中具体漏洞的流量引用，保留顺序；交接后 report_finding 可传 evidence_hint_id 携带这些引用。", "items": obj(map[string]any{"traffic_id": str("真实流量 ID"), "role": str("baseline / proof / verification / supporting"), "note": str("该流量支持什么结论")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d 必须是本任务的提示节点（继承提示不可直接用于绑定）", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
