package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 代码审计平台不抓包、不出网：漏洞↔流量绑定永久关闭（findingTrafficBindingEnabled()
// 恒定 false）。所以这里断言的不是「开关生效」，而是「开关怎么拨都没有流量交接」——
// 工具表里不出现 bind_finding_traffic，guidance 不含 traffic_refs，
// report_finding / add_hint 的 schema 也不带流量参数；同时用户自定义的描述与提示词不被改写。
// 关闭绑定后 report_finding 仍带 retest_packets（按接口逐份的推演复测报文），它是非证据的复测用例。
func TestFindingWorkflowSharedAssemblyAndSwitch(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	on := false
	FindingTrafficBindingEnabled = func() bool { return on }
	ts := NewToolSet(nil, "fixture")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		out := make([]actool.CoreTool, len(base))
		for i, tool := range base {
			out[i] = DecorateTool(tool, "CUSTOM DESCRIPTION", tool.InputSchema())
		}
		return out
	}
	for _, role := range []string{"worker", "planner", "mainagent", "auto", "pentest", "custom-agent"} {
		for _, enabled := range []bool{false, true, false} {
			on = enabled
			out, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{ts.addFinding(), ts.addHint()})
			cleanup()
			system, _ := deferredSystem("USER CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
				t.Fatal("custom prompt replaced")
			}
			if strings.Contains(system[0], "traffic_refs") {
				t.Fatalf("%s: 流量交接说明不应再出现（开关取值 %v 无效）", role, enabled)
			}
			if strings.Contains(def.FindingGuidance, "traffic_refs") || strings.Contains(def.FindingGuidance, "bind_finding_traffic") {
				t.Fatalf("%s: 关闭绑定时不应产生流量交接说明: %q", role, def.FindingGuidance)
			}
			// 关闭绑定后仍有「推演复测报文」的生成规约（不抓包平台用它填详情页的原始数据包）。
			if !strings.Contains(def.FindingGuidance, "复测报文") {
				t.Fatalf("%s: report_finding 存在时应给出复测报文规约: %q", role, def.FindingGuidance)
			}
			for _, tool := range out {
				if tool.Name() == "bind_finding_traffic" {
					t.Fatalf("%s: bind_finding_traffic 不应出现在工具表里", role)
				}
				if !strings.HasPrefix(tool.Description(), "CUSTOM DESCRIPTION") {
					t.Fatal("custom description replaced")
				}
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				json.Unmarshal(raw, &schema)
				props := schema["properties"].(map[string]any)
				if props["traffic_refs"] != nil {
					t.Fatalf("%s: 流量参数应被剥掉（开关取值 %v 无效）", role, enabled)
				}
				if tool.Name() == "report_finding" && props["retest_packets"] == nil {
					t.Fatalf("%s: 剥流量参数时不应连带删掉 retest_packets", role)
				}
				if tool.Name() == "add_hint" {
					nested := props["hints"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
					if nested["traffic_refs"] != nil {
						t.Fatal("nested hint schema still carries traffic refs")
					}
				}
			}
		}
	}
	on = true
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	out, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{ts.addFinding()})
	defer cleanup()
	if len(out) != 0 || def.FindingGuidance != "" {
		t.Fatal("reintroduced disabled tool or its guidance")
	}
}
