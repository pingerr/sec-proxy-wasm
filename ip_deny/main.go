package main

import (
	"bytes"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"ip_deny/ipfilter"
)

func main() {
	wrapper.SetCtx(
		"waf-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type IpConfig struct {
	f ipfilter.IPFilter
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	//获取黑名单配置
	result := json.Get("ip_blacklist")
	for _, ipBlack := range result.Array() {
		if bytes.IndexByte([]byte(ipBlack.String()), '/') < 0 {
			if err := config.f.AddIPString(ipBlack.String()); err != nil {
				return err
			}
		} else {
			if err := config.f.AddIPNetString(ipBlack.String()); err != nil {
				return err
			}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")
	log.Infof("[xRealIp: %]", xRealIp)
	if config.f.FilterIPString(xRealIp) {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}
	return types.ActionContinue
}
