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

	var buf bytes.Buffer
	for i := range results {
		buf.WriteString(results[i].Str)
		if index := bytes.IndexByte(buf.Bytes(), '/'); index < 0 {
			buf.WriteString("/32")
		}
		_, ipNet, err := net.ParseCIDR(buf.String())
		if err != nil {
			log.Errorf("[parseCTDR error：%s]", buf.String())
		}
		config.f.Add(config.id, *ipNet)
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {

	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.Get(net.ParseIP(xRealIp)) == 1 {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}

	return types.ActionContinue
}
