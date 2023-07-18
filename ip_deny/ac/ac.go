package ac

import (
	"bytes"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	goahocorasick "github.com/anknown/ahocorasick"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
)

type IpConfig struct {
	ac *goahocorasick.Machine
}

func FilterStart() {
	wrapper.SetCtx(
		"ip-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func parseConfig(json gjson.Result, config *IpConfig, log wrapper.Log) error {
	dict := [][]rune{}

	//获取黑名单配置
	result := json.Get("ip_blacklist").Array()

	for i := range result {
		if index := bytes.IndexByte([]byte(result[i].String()), '/'); index < 0 {
			dict = append(dict, bytes.Runes(ipAddrToBiStr(result[i].String(), 32)))
		} else {
			mask, _ := strconv.Atoi(result[i].String()[index+1:])
			dict = append(dict, bytes.Runes(ipAddrToBiStr(result[i].String(), mask)))
		}
	}

	m := new(goahocorasick.Machine)
	if err := m.Build(dict); err != nil {
		log.Info("AC Machine build error")
	}
	config.ac = m

	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config IpConfig, log wrapper.Log) types.Action {
	xRealIp, _ := proxywasm.GetHttpRequestHeader("x-real-ip")
	terms := config.ac.MultiPatternSearch([]rune(xRealIp), true)

	if len(terms) > 0 {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by ip"), -1); err != nil {
			panic(err)
		}
	}

	return types.ActionContinue
}

//func ReadRunes(filename string) ([][]rune, error) {
//	var dict [][]rune
//
//	f, err := os.OpenFile(filename, os.O_RDONLY, 0660)
//	if err != nil {
//		return nil, err
//	}
//
//	r := bufio.NewReader(f)
//	for {
//		l, err := r.ReadBytes('\n')
//		if err != nil || err == io.EOF {
//			break
//		}
//		l = bytes.TrimSpace(l)
//		dict = append(dict, bytes.Runes(l))
//	}
//
//	return dict, nil
//}

//func main() {
//	dict, err := ReadRunes("your_dict_files")
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	content := []rune("your text")
//
//	m := new(goahocorasick.Machine)
//	if err := m.Build(dict); err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	terms := m.MultiPatternSearch(content, false)
//	for _, t := range terms {
//		fmt.Printf("%d %s\n", t.Pos, string(t.Word))
//	}
//}

func ipAddrToBiStr(ipAddr string, mask int) []byte {
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
	//buf = append(buf, '^')
	for i := range ipArr {
		buf = AppendBinaryString(buf, ipArr[i])
	}
	return buf[0:mask]
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
