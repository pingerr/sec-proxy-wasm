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

type CCConfig struct {
	headerQps uint8
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {
	_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	return types.ActionContinue
}
