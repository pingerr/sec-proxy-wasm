package denyall

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

func PluginStart() {
	wrapper.SetCtx(
		"waf-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type WafConfig struct {
	waf uint8
}

func parseConfig(json gjson.Result, config *WafConfig, log wrapper.Log) error {
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config WafConfig, log wrapper.Log) types.Action {
	_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	return types.ActionContinue
}
