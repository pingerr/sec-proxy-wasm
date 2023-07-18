package hs

import (
	"bytes"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/flier/gohs/hyperscan"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
)

type Match struct {
	from uint64
	to   uint64
}

type IpConfig struct {
	db hyperscan.BlockDatabase
	sc *hyperscan.Scratch
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	var ps []*hyperscan.Pattern

	//获取黑名单配置
	result := json.Get("ip_blacklist").Array()

	for i := range result {
		if index := bytes.IndexByte([]byte(result[i].String()), '/'); index < 0 {
			ps = append(ps, hyperscan.NewPattern(ipAddrToBiStr(result[i].String(), 32), hyperscan.DotAll|hyperscan.SomLeftMost))
		} else {
			mask, _ := strconv.Atoi(result[i].String()[index+1:])
			ps = append(ps, hyperscan.NewPattern(ipAddrToBiStr(result[i].String()[0:index], mask), hyperscan.DotAll|hyperscan.SomLeftMost))
		}
	}
	db, err := hyperscan.NewBlockDatabase(ps...)
	if err != nil {
		panic(err)
	}
	config.db = db
	s, err := hyperscan.NewScratch(db)
	if err != nil {
		panic(err)
	}
	config.sc = s

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")

	var matches []Match

	handler := hyperscan.MatchHandler(func(id uint, from, to uint64, flags uint, context interface{}) error {
		if len(matches) == 0 {
			matches = append(matches, Match{from, to})
		}
		return nil
	})
	_ = config.db.Scan([]byte(xRealIp), config.sc, handler, nil)
	if len(matches) > 0 {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}

	return types.ActionContinue
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

	buf := make([]byte, 0, 33)
	buf = append(buf, '^')
	for i := range ipArr {
		buf = AppendBinaryString(buf, ipArr[i])
	}
	return string(buf[0 : mask+1])
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

//
//func HsTest(ipArr []string) {
//	var ps []*hyperscan.Pattern
//	for i := range ipArr {
//		//pre, _ := netip.ParsePrefix(ipArr[i] + "/" + "24")
//		biStr := ipAddrToBiStr(ipArr[i], 24)
//		ps = append(ps, hyperscan.NewPattern(biStr, hyperscan.DotAll|hyperscan.SomLeftMost))
//		fmt.Println(biStr)
//	}
//	db, err := hyperscan.NewBlockDatabase(ps...)
//	if err != nil {
//		panic(err)
//	}
//	s, err := hyperscan.NewScratch(db)
//	if err != nil {
//		panic(err)
//	}
//	var matches []Match
//
//	handler := hyperscan.MatchHandler(func(id uint, from, to uint64, flags uint, context interface{}) error {
//		if len(matches) == 0 {
//			matches = append(matches, Match{from, to})
//		}
//		return nil
//	})
//
//	for i := range ipArr {
//		if err := db.Scan([]byte(ipArr[i]), s, handler, nil); err != nil {
//			fmt.Println(true)
//		} else {
//			if len(matches) > 0 {
//				fmt.Println(false)
//			}
//		}
//		matches = matches[0:0]
//	}
//}
//
