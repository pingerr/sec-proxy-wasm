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
	config.f = cidranger.NewPCTrieRanger()
	//获取黑名单配置
	result := json.Get("ip_blacklist")

	for _, ipBlack := range result.Array() {
		if bytes.IndexByte([]byte(ipBlack.String()), '/') < 0 {
			if bytes.IndexByte([]byte(ipBlack.String()), '.') >= 0 {
				_, network, _ := net.ParseCIDR(ipBlack.String() + "/" + "32")
				err := config.f.Insert(newCustomRangerEntry(*network))
				if err != nil {
					log.Errorf("[ipv4 insert error: %s]", ipBlack.String())
				}
			} else if bytes.IndexByte([]byte(ipBlack.String()), ':') >= 0 {
				log.Infof("[ipv6 info: %s]", ipBlack.String())
				_, network, _ := net.ParseCIDR(ipBlack.String() + "/" + "128")
				err := config.f.Insert(newCustomRangerEntry(*network))
				if err != nil {
					log.Errorf("[ipv6 insert error: %s]", ipBlack.String())
				}
			}
		} else {
			log.Infof("[CIDR str: %s]", ipBlack.String())
			_, network, _ := net.ParseCIDR(ipBlack.String())
			err := config.f.Insert(newCustomRangerEntry(*network))
			if err != nil {
				log.Errorf("[cidr insert error: %s]", ipBlack.String())
			}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")
	if length := len(xRealIp); length > 15 {
		log.Infof("[xRealIp: %s]", xRealIp)
	}
	contains, _ := config.f.Contains(net.ParseIP(xRealIp))
	if contains {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}
	return types.ActionContinue
}
