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
	f cidranger.Ranger
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
	//var ms runtime.MemStats
	//runtime.ReadMemStats(&ms)
	//log.Infof("[%s] Alloc:%d(bytes) HeapIdle:%d(bytes) HeapReleased:%d(bytes)", "ip start (cidranger)", ms.Alloc, ms.HeapIdle, ms.HeapReleased)

	config.f = cidranger.NewPCTrieRanger()
	//获取黑名单配置
	result := json.Get("ip_blacklist")

	for _, ipBlack := range result.Array() {
		if bytes.IndexByte([]byte(ipBlack.String()), '/') < 0 {
			if bytes.IndexByte([]byte(ipBlack.String()), '.') >= 0 {
				_, network, _ := net.ParseCIDR(ipBlack.String() + "/" + "32")
				_ = config.f.Insert(newCustomRangerEntry(*network))

			} else if bytes.IndexByte([]byte(ipBlack.String()), ':') >= 0 {
				_, network, _ := net.ParseCIDR(ipBlack.String() + "/" + "128")
				_ = config.f.Insert(newCustomRangerEntry(*network))

			}
		} else {
			_, network, _ := net.ParseCIDR(ipBlack.String())
			_ = config.f.Insert(newCustomRangerEntry(*network))
		}
	}
	//runtime.ReadMemStats(&ms)
	//log.Infof("[%s] Alloc:%d(bytes) HeapIdle:%d(bytes) HeapReleased:%d(bytes)", "ip end (cidranger)", ms.Alloc, ms.HeapIdle, ms.HeapReleased)
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	contains, _ := config.f.Contains(net.ParseIP(xRealIp))
	if contains {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}
	return types.ActionContinue
}

//func traceMemStats(log wrapper.Log, name string) {
//	var ms runtime.MemStats
//	runtime.ReadMemStats(&ms)
//	log.Infof("[%s] Alloc:%d(bytes) HeapIdle:%d(bytes) HeapReleased:%d(bytes)", name, ms.Alloc, ms.HeapIdle, ms.HeapReleased)
//}
