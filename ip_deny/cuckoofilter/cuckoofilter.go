package cuckoofilter

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/linvon/cuckoo-filter"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"net"
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

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
