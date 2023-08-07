package ipLook

import (
	"bytes"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"net"
)

type IpConfig struct {
	f  *Tree
	id SID
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	config.f = New()
	config.id = 1
	//获取黑名单配置
	results := json.Get("ip_blacklist").Array()

	for i := range results {
		buf := bytes.NewBufferString(results[i].Str)
		if index := bytes.IndexByte(buf.Bytes(), '/'); index < 0 {
			buf.WriteString("/32")
		}
		_, ipNet, _ := net.ParseCIDR(buf.String())
		config.f.Add(config.id, *ipNet)
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {

	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.Get(ParseIPv4(xRealIp)) == config.id {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}

	return types.ActionContinue
}
