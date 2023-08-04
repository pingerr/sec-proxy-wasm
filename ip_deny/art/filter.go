package art

import (
	"bytes"
	"fmt"
	art "github.com/plar/go-adaptive-radix-tree"
	"strconv"
	"strings"
)

type IpConfig struct {
	f art.Tree
}

//func FilterStart() {
//	wrapper.SetCtx(
//		"ip-deny",
//		wrapper.ParseConfigBy(parseConfig),
//		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
//	)
//}
//
//func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
//	config.f = art.New()
//	//获取黑名单配置
//	results := json.Get("ip_blacklist").Array()
//
//	for i := range results {
//
//		err := config.f.SetCIDR(results[i].String(), 1)
//		if err != nil {
//			//log.Errorf("[insert cidr error: %s]", results[i].String())
//			panic(err)
//		}
//	}
//	return nil
//}
//
//func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
//
//	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")
//
//	if v, err := config.f.FindCIDR(xRealIp); err == nil && v == 1 {
//		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1)
//	}
//
//	return types.ActionContinue
//}

func RadixTest(ipArr []string) {
	f := art.New()
	var ipPre string
	for i := range ipArr {

		if index := bytes.IndexByte([]byte(ipArr[i]), '/'); index < 0 {
			ipPre = ipMaskToBiStr(ipArr[i], 24)
		} else {
			//mask, _ := strconv.Atoi(ipArr[i][index+1:])
			ipPre = ipMaskToBiStr(ipArr[i], 24)
		}
		//fmt.Println(ipPre)
		//fmt.Println(ipPre)
		//fmt.Println(len(ipPre))
		f.Insert(art.Key(ipPre), 1)
	}
	//f.Insert(art.Key("1.2.3.4"), 1)
	//f.Insert(art.Key("4.2.3.4/8"), 1)

	//ipArr = append(ipArr, "123.123.123.321")
	//var found bool
	for i := range ipArr {
		_, found := f.Search(art.Key(ipAddrToBiStr(ipArr[i])))
		fmt.Println(found)
	}
}

func ipMaskToBiStr(ipAddr string, mask int) string {

	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)
	out := strconv.FormatInt(sum, 2)

	return out[0 : mask-(32-len(out))]
}

func ipAddrToBiStr(ipAddr string) string {

	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum int64
	sum += int64(b0) << 24
	sum += int64(b1) << 16
	sum += int64(b2) << 8
	sum += int64(b3)

	return strconv.FormatInt(sum, 2)
}
