package ccfilter

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"math/rand"
)

func PluginStart() {
	wrapper.SetCtx(
		"cc-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type CCConfig struct {
	test int
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	config.test = 1

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {
	ran := rand.Intn(2)
	if ran%2 == 0 {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	}

	//if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1); err != nil {
	//	panic(err)
	//}
	return types.ActionContinue
}
