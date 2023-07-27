package cuckoofilter

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/linvon/cuckoo-filter"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

type IpConfig struct {
	f *cuckoo.Filter
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	config.f = cuckoo.NewFilter(4, 9, 3900, cuckoo.TableTypePacked)
	//获取黑名单配置
	result := json.Get("ip_blacklist")
	for _, ipBlack := range result.Array() {
		config.f.Add([]byte(ipBlack.String()))
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	log.Infof("[xRealIp: %s]", xRealIp)

	if config.f.Contain([]byte(xRealIp)) {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}
	return types.ActionContinue
}
