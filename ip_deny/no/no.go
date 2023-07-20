package no

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/yl2chen/cidranger"
)

type IpConfig struct {
	f cidranger.Ranger
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	config.f = cidranger.NewPCTrieRanger()
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
		panic(err)
	}
	return types.ActionContinue
}
