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
			ipPre = ipAddrToBiStr(ipArr[i], 24)
		} else {
			mask, _ := strconv.Atoi(ipArr[i][index+1:])
			ipPre = ipAddrToBiStr(ipArr[i][0:index], mask)
		}
		//fmt.Println(ipPre)
		f.Insert(art.Key(ipPre), 1)
	}
	//f.Insert(art.Key("1.2.3.4"), 1)
	//f.Insert(art.Key("4.2.3.4/8"), 1)

	//ipArr = append(ipArr, "123.123.123.321")
	var found bool
	for i := range ipArr {
		ipPre = ipAddrToBiStr(ipArr[i], 32)
		_, found = f.Search(art.Key(ipPre))
		fmt.Println(found)
	}
}

func ipAddrToBiStr(ipAddr string, mask int) string {

	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var ipArr [4]byte
	ipArr[0] = byte(b0)
	ipArr[1] = byte(b1)
	ipArr[2] = byte(b2)
	ipArr[3] = byte(b3)

	buf := make([]byte, 0, 32)
	for i := range ipArr {
		buf = AppendBinaryString(buf, ipArr[i])
	}
	return string(buf[0:mask])
}

func AppendBinaryString(bs []byte, b byte) []byte {
	var a byte
	for i := 0; i < 8; i++ {
		a = b
		b <<= 1
		b >>= 1
		switch a {
		case b:
			bs = append(bs, byte('0'))
		default:
			bs = append(bs, byte('1'))
		}
		b <<= 1
	}
	return bs
}
