package radixTree

import (
	"fmt"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"github.com/zmap/go-iptree/iptree"
)

type IpConfig struct {
	f *iptree.IPTree
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	config.f = iptree.New()
	//获取黑名单配置
	result := json.Get("ip_blacklist").Array()

	for i := range result {
		err := config.f.AddByString(result[i].String(), 1)
		if err != nil {
			log.Errorf("[insert cidr error: %s]", result[i].String())
			panic(err)
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {

	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	if _, found, err := config.f.GetByString(xRealIp); err == nil && found {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
	}

	return types.ActionContinue
}

func RadixTest(ipArr []string) {
	f := iptree.New()
	for i := range ipArr {
		err := f.AddByString(ipArr[i], 1)
		if err != nil {
			fmt.Printf("[insert error； %s]", ipArr[i])
		}

	}
	err := f.AddByString("1.2.3.4", 1)
	if err != nil {
		fmt.Printf("[insert error； %s]", "1.2.3.4")
	}
	err1 := f.AddByString("4.2.3.4/8", 1)
	if err1 != nil {
		fmt.Printf("[insert error； %s]", "1.2.3.4")
	}

	ipArr = append(ipArr, "123.123.123.321")

	for i := range ipArr {
		_, _, _ = f.GetByString(ipArr[i])
		//fmt.Println(found)
	}
}
