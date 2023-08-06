package myRadixTree

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

type IpConfig struct {
	f *Tree
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	config.f = NewTree(0)
	//获取黑名单配置
	results := json.Get("ip_blacklist").Array()

	for i := range results {
		err := config.f.SetCIDRb([]byte(results[i].Str), 1)
		if err != nil {
			//log.Errorf("[insert cidr error: %s]", results[i].String())
			panic(err)
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {

	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if v, _ := config.f.FindCIDRb([]byte(xRealIp)); v == 1 {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}

	return types.ActionContinue
}

func RadixTest(ipArr []string, f *Tree) {
	//f := NewTree(0)
	//for i := range ipArr {
	//	_ = f.SetCIDRb([]byte(ipArr[i]), 1)
	//
	//}

	for i := range ipArr {
		_, _ = f.FindCIDRb([]byte(ipArr[i]))
		//fmt.Println(found)
	}
}
