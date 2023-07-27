package ccfilter

import (
	json2 "encoding/json"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
	"strconv"
	"time"
)

func PluginStart() {
	wrapper.SetCtx(
		"cc-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type CCConfig struct {
	headerKey       string
	cookieKey       string
	qps             int
	qpm             int
	qpd             int
	headerBlockTime int
	cookieBlockTime int
	hasHeaderBlock  bool
	hasCookieBlock  bool
	headerMap       map[string]*MyLimiter
	cookieLmt       map[string]*MyLimiter
}

type MyLimiter struct {
	qps *rate.Limiter
	qpm *rate.Limiter
	//qpd          rate.Limiter
	hasBlockTime bool
	nextTime     int64
	blockTime    int
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	result := json.Get("cc_rules").Array()

	for i := range result {
		rule := make(map[string]string)
		err := json2.Unmarshal([]byte(result[i].String()), &rule)
		if err != nil {
			log.Errorf("[json parse error: %s]", result[i].String())
		}
		var limiter MyLimiter

		if qpsStr, isOk := rule["qps"]; isOk {
			qps, _ := strconv.Atoi(qpsStr)
			config.qps = qps
			//limiter.qps = rate.NewLimiter(rate.Every(time.Second), qps)
		}
		if qpmStr, isOk := rule["qpm"]; isOk {
			qpm, _ := strconv.Atoi(qpmStr)
			config.qpm = qpm
			//limiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), qpm)
		}
		if blockSeconds, isOk := rule["block_seconds"]; isOk {
			bs, _ := strconv.Atoi(blockSeconds)

			limiter.hasBlockTime = true
			limiter.blockTime = bs
			limiter.nextTime = time.Now().Unix()
		}
		if header, isOk := rule["header"]; isOk {
			config.headerKey = header
			config.headerLmt = &limiter
		}
		//if cookie, isOk := rule["cookie"]; isOk {
		//	config.cookieKey = cookie
		//	config.cookieLmt = &limiter
		//}

	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {

	headerValue, err := proxywasm.GetHttpRequestHeader(config.headerName)
	if err != nil {
		log.Errorf("[header get error, %s]", config.headerName)
	}
	now := time.Now().Unix()
	if config.headerLmt.hasBlockTime && now < config.headerLmt.nextTime {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		return types.ActionContinue
	}
	if config.headerLmt.qps.Allow() && config.headerLmt.qpm.Allow() {
		return types.ActionContinue
	}
	//if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1); err != nil {
	//	panic(err)
	//}
	return types.ActionContinue
}
