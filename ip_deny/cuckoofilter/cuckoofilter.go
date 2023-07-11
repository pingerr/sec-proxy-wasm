package cuckoofilter

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/linvon/cuckoo-filter"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"runtime"
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
	traceMemStats(log, "ip start (cuckoo filter)")
	config.f = cuckoo.NewFilter(4, 9, 3900, cuckoo.TableTypePacked)
	//获取黑名单配置

	for _, ipBlack := range json.Get("ip_blacklist").Array() {
		config.f.Add([]byte(ipBlack.String()))
	}
	traceMemStats(log, "ip end (cuckoo filter)")
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.Contain([]byte(xRealIp)) {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}
	return types.ActionContinue
}

func traceMemStats(log wrapper.Log, name string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	log.Infof("[%s] Alloc:%d(bytes) HeapIdle:%d(bytes) HeapReleased:%d(bytes)", name, ms.Alloc, ms.HeapIdle, ms.HeapReleased)
}
