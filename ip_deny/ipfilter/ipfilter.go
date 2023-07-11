package ipfilter

import (
	"bytes"
	"errors"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"net"
	"runtime"
)

type IPFilter struct {
	ipnets []net.IPNet
	ips    []net.IP
}

type IpConfig struct {
	f IPFilter
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	traceMemStats(log, "ip start")
	//获取黑名单配置
	result := json.Get("ip_blacklist")
	for _, ipBlack := range result.Array() {
		if bytes.IndexByte([]byte(ipBlack.String()), '/') < 0 {
			_ = config.f.AddIPString(ipBlack.String())
		} else {
			_ = config.f.AddIPNetString(ipBlack.String())
		}
	}
	traceMemStats(log, "ip end")
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.FilterIPString(xRealIp) {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}
	return types.ActionContinue
}

func (f *IPFilter) FilterIP(ip net.IP) bool {
	for _, item := range f.ipnets {
		return item.Contains(ip)
	}
	for _, item := range f.ips {
		return item.Equal(ip)
	}
	return false
}

func (f *IPFilter) FilterIPString(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return f.FilterIP(ip)
}

func (f *IPFilter) AddIPNet(item net.IPNet) {
	f.ipnets = append(f.ipnets, item)
}

func (f *IPFilter) AddIPNetString(s string) error {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}
	f.AddIPNet(*ipnet)
	return nil
}

func (f *IPFilter) AddIP(ip net.IP) {
	f.ips = append(f.ips, ip)
}

func (f *IPFilter) AddIPString(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return errors.New("Parse IP Error: " + s)
	}
	f.AddIP(ip)
	return nil
}

func traceMemStats(log wrapper.Log, name string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	log.Infof("[%s] Alloc:%d(bytes) HeapIdle:%d(bytes) HeapReleased:%d(bytes)", name, ms.Alloc, ms.HeapIdle, ms.HeapReleased)
}
