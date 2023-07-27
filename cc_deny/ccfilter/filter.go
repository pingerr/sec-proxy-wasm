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
	headerBlockTime int64
	cookieBlockTime int64
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
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	result := json.Get("cc_rules").Array()

	for i := range result {
		rule := make(map[string]string)
		err := json2.Unmarshal([]byte(result[i].String()), &rule)
		if err != nil {
			log.Errorf("[json parse error: %s]", result[i].String())
		}
		//var limiter MyLimiter
		log.Infof("[cc config: %s]", result[i].String())
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
			config.headerBlockTime = int64(bs)
			config.hasHeaderBlock = true
			//limiter.hasBlockTime = true
			//limiter.blockTime = bs
			//limiter.nextTime = time.Now().Unix()
		}
		if headerKey, isOk := rule["header"]; isOk {
			config.headerKey = headerKey
			//config.headerLmt = &limiter
		}
		//if cookie, isOk := rule["cookie"]; isOk {
		//	config.cookieKey = cookie
		//	config.cookieLmt = &limiter
		//}

	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {

	headerValue, err := proxywasm.GetHttpRequestHeader(config.headerKey)
	if err != nil {
		log.Errorf("[header get error, %s]", config.headerKey)
	}
	now := time.Now()
	limiter, isOk := config.headerMap[headerValue]
	if !isOk {
		var myLimiter MyLimiter
		myLimiter.qps = rate.NewLimiter(rate.Every(time.Second), config.qps)
		myLimiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), config.qpm)
		myLimiter.hasBlockTime = config.hasHeaderBlock
		myLimiter.nextTime = now.UnixMilli()
		return types.ActionContinue
	}

	if limiter.hasBlockTime && now.UnixMilli() < limiter.nextTime {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		return types.ActionContinue
	} else {
		if limiter.qps.Allow() && limiter.qpm.Allow() {
			return types.ActionContinue
		} else {
			_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			if limiter.hasBlockTime {
				limiter.nextTime = now.UnixMilli() + config.headerBlockTime*1000
			}
		}
	}
	return types.ActionContinue
}
