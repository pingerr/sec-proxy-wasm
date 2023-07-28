package ipfilter

import (
	"bytes"
	"errors"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"net"
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
	//获取黑名单配置
	result := json.Get("ip_blacklist")
	for _, ipBlack := range result.Array() {
		if bytes.IndexByte([]byte(ipBlack.String()), '/') < 0 {
			if err := config.f.AddIPString(ipBlack.String()); err != nil {
				log.Errorf("[insert ip failed: %s]", ipBlack.String())
				panic(err)
			}
		} else {
			if err := config.f.AddIPNetString(ipBlack.String()); err != nil {
				log.Errorf("[insert ip failed: %s]", ipBlack.String())
				panic(err)
			}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.FilterIPString(xRealIp) {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}
	return types.ActionContinue
}

func (f *IPFilter) FilterIP(ip net.IP) bool {
	for _, item := range f.ipnets {
		if item.Contains(ip) {
			return true
		}
	}
	for _, item := range f.ips {
		if item.Equal(ip) {
			return true
		}
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
