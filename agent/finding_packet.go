package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// retestPacketArg 是 report_finding 的 retest_packets 数组里的一项（一份报文 = 一个接口）。
//
// 平台不抓包，漏洞详情页的「原始数据包」在没有真实流量证据时改由模型推演。
// 这份推演是**复测用例，不是证据**：它单独落 finding_packets 表，不写证据表、
// 不进证据版本、不参与导出，页面上也必须与真实抓包区分展示。
type retestPacketArg struct {
	// AssetID 是这份报文对应的接口资产 id。报文里写死了 Host 与路径，
	// 一份报文只可能覆盖一个接口，所以归属必须显式声明，不能靠猜。
	AssetID      json.RawMessage `json:"asset_id"`
	RawRequest   string          `json:"raw_request"`
	RawResponse  string          `json:"raw_response"`
	GroundedRefs []string        `json:"grounded_refs"`
	Assumptions  []string        `json:"assumptions"`
}

// RetestPacketSchema 是 report_finding 的 retest_packets 参数 schema。
//
// 导出给 server 的一次性迁移复用：运行时的 schema 以 tools 表为准（ToolResolve 用
// row.Schema 装饰工具），而 SeedTool 是首插入only，所以老库必须靠迁移补这个属性。
// 两处必须是同一份定义，否则模型看到的参数与代码里的解析会漂移。
func RetestPacketSchema() map[string]any {
	return map[string]any{
		"type": "array",
		"description": "可选（非证据）：按【每个涉及接口一份】推演的复测报文数组。" +
			"报文里写死了 Host、路径与参数，一份报文只对应一个接口，所以每一份都必须用 asset_id 声明它属于哪个接口——" +
			"一个漏洞涉及 N 个接口就交 N 份，**不要只写一份代表全部**（那会让复测打错目标）。" +
			"非 HTTP 漏洞省略该参数。",
		"items": obj(map[string]any{
			"asset_id": intp("这份报文对应哪个接口资产：传 asset_ids 里那个接口的 id（list_assets 返回的接口资产 id）。必填——服务端会拿它核对报文的方法/路径与该接口一致，并对不上时按「未指定接口」保存并标记。"),
			"raw_request": str("依据源码推演、可直接粘贴复测的完整 HTTP/1.1 请求报文：起始行 + Host 等头部 + 空行 + 正文。路径与参数必须与 asset_id 指向的那个接口一致，字段取值必须有源码依据，凭证一律写 <占位符>。平台不抓包，这是**非证据**的复测用例，只是供人复测。"),
			"raw_response": str("可选：同一请求的预期响应报文（同为推演产物，仅作参考）"),
			"grounded_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "每条报文取值的源码依据，格式 文件:行号（例如 src/main/java/com/x/UserController.java:88）"},
			"assumptions": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "无法从源码确定、按假设填写的值（例如会话凭证、运行时生成的 ID）"},
		}, "asset_id", "raw_request"),
	}
}

// saveRetestPackets 逐接口保存推演报文，返回给模型的状态与说明。
//
// 刻意独立于漏洞入库事务：漏洞已经确认落库，报文只是辅助产物，任何保存/校验
// 失败都不应该让 report_finding 失败——否则模型会因为一个可选字段丢掉整个漏洞。
// 逐份保存还保证「一个接口失败」不会连带丢掉其它接口已经写好的报文。
func (t *ToolSet) saveRetestPackets(ctx context.Context, findingID int64, findingAssetIDs []int64, pkts []retestPacketArg) (string, string) {
	submitted := 0
	for _, p := range pkts {
		if strings.TrimSpace(p.RawRequest) != "" {
			submitted++
		}
	}
	if submitted == 0 {
		return "", ""
	}
	if t.ts == nil {
		return "error", "复测报文未保存：缺少任务上下文。"
	}

	var (
		saved   int
		invalid []string
		failed  []string
	)
	for _, p := range pkts {
		if strings.TrimSpace(p.RawRequest) == "" {
			continue
		}
		assetID := pid(p.AssetID)
		v, err := t.ts.SaveRetestPacket(ctx, findingID, assetID, findingAssetIDs, db.RetestPacketInput{
			AssetID:      assetID,
			RawRequest:   p.RawRequest,
			RawResponse:  p.RawResponse,
			GroundedRefs: p.GroundedRefs,
			Assumptions:  p.Assumptions,
			Generator:    t.worker,
			Source:       db.RetestPacketSourceLLM,
		})
		label := "未指定接口"
		if assetID > 0 {
			label = fmt.Sprintf("接口 #%d", assetID)
		}
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("%s：%s", label, err.Error()))
		case v.Valid:
			saved++
		default:
			saved++
			invalid = append(invalid, fmt.Sprintf("%s：%s", label, strings.Join(v.Errors, "；")))
		}
	}

	switch {
	case len(failed) > 0 && saved == 0:
		return "error", "复测报文保存失败：" + strings.Join(failed, "；")
	case len(invalid) > 0:
		note := fmt.Sprintf("已按接口保存 %d 份复测报文，其中 %d 份未通过校验：%s。它们仍是按源码推演的复测用例、不是抓包证据；"+
			"不要为此重复上报同一个漏洞，请在 evidence 里说明偏差，或让人在漏洞详情页修订对应接口的报文。",
			saved, len(invalid), strings.Join(invalid, "；"))
		if len(failed) > 0 {
			note += "另有保存失败：" + strings.Join(failed, "；")
		}
		return "invalid", note
	case len(failed) > 0:
		return "error", fmt.Sprintf("已保存 %d 份复测报文，另有 %d 份保存失败：%s", saved, len(failed), strings.Join(failed, "；"))
	default:
		return "saved", fmt.Sprintf("已按接口保存 %d 份复测报文并通过校验。每份只对应它声明的那个接口；"+
			"它们是按源码推演的复测用例、不是抓包证据，不能替代 evidence 里的源码结论。", saved)
	}
}
