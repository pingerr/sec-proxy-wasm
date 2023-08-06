package flashTrie

import (
	"fmt"
	"github.com/1995parham/FlashTrie.go/net"
	"github.com/1995parham/FlashTrie.go/pctrie"
	"github.com/1995parham/FlashTrie.go/trie"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
)

type IpConfig struct {
	f *pctrie.PCTrie
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	trieTree := trie.New()

	//获取黑名单配置
	results := json.Get("ip_blacklist").Array()

	for i := range results {
		r, _ := net.ParseNet(results[i].String())
		trieTree.Add(r, "A")
	}
	config.f = pctrie.New(trieTree, 4)
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {

	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if config.f.Lookup(net.ParseIP(xRealIp)) != "" {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}

	return types.ActionContinue
}

func RadixTest(ipArr []string) {
	trieTree := trie.New()
	//获取黑名单配置

	for i := range ipArr {
		r, _ := net.ParseNet(ipArr[i] + "/" + "24")
		trieTree.Add(r, "A")
	}
	f := pctrie.New(trieTree, len(ipArr)+1)
	for i := range ipArr {
		a := f.Lookup(ipArr[i])
		if a != "" {
			//fmt.Printf("[insert error； %s]", ipArr[i])
		}

	}

	for i := range ipArr {
		a := f.Lookup(ipArr[i])
		fmt.Printf(a)
	}
}
