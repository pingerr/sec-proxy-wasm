package cidranger

import (
	"bytes"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/yl2chen/cidranger"
	"net"
)

type IpConfig struct {
	f     cidranger.Ranger
	index int
}

type customRangerEntry struct {
	ipNet net.IPNet
}

func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func (b *customRangerEntry) NetworkStr() string {
	return b.ipNet.String()
}

func newCustomRangerEntry(ipNet net.IPNet) cidranger.RangerEntry {
	return &customRangerEntry{
		ipNet: ipNet,
	}
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
	//获取黑名单配置
	result := json.Get("ip_blacklist").Array()

	config.index = 0

	for i := range result {
		var ip bytes.Buffer
		if bytes.IndexByte([]byte(result[i].String()), '/') < 0 {
			//if bytes.IndexByte([]byte(result[i].String()), '.') >= 0 {
			ip.WriteString(result[i].String())
			ip.WriteString("/32")
			_, network, _ := net.ParseCIDR(ip.String())
			_ = config.f.Insert(newCustomRangerEntry(*network))
			//if err != nil {
			//	log.Errorf("[ipv4 insert error: %s]", ipBlack.String())
			//}
			//} else if bytes.IndexByte([]byte(result[i].String()), ':') >= 0 {
			//	_, network, _ := net.ParseCIDR(result[i].String() + "/" + "128")
			//	_ = config.f.Insert(newCustomRangerEntry(*network))
			//	//if err != nil {
			//	//	log.Errorf("[ipv6 insert error: %s]", ipBlack.String())
			//	//}
			//}
		} else {
			_, network, _ := net.ParseCIDR(result[i].String())
			_ = config.f.Insert(newCustomRangerEntry(*network))
			//if err != nil {
			//	log.Errorf("[cidr insert error: %s]", ipBlack.String())
			//}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	if config.index == 0 {
		config.index = 1
	} else {

		xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

		contains, _ := config.f.Contains(net.ParseIP(xRealIp))
		if contains {
			if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
				panic(err)
			}
		}
	}

	return types.ActionContinue
}

func CidrangerTest(ipArr []string) {
	f := cidranger.NewPCTrieRanger()
	for i := range ipArr {
		_, network, _ := net.ParseCIDR(ipArr[i] + "/" + "24")
		_ = f.Insert(newCustomRangerEntry(*network))
	}

	for i := range ipArr {
		_, _ = f.Contains(net.ParseIP(ipArr[i]))
		//fmt.Println(contains)
	}
}
