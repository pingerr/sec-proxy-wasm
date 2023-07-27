package ccfilter

import (
	json2 "encoding/json"
	"fmt"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
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

type CCRule struct {
	Header       string `json:"header"`
	Qps          int    `json:"qps"`
	Qpm          int    `json:"qpm"`
	Qpd          int    `json:"qpd"`
	BlockSeconds int64  `json:"block_seconds"`
	Cookie       string `json:"cookie"`
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	result := json.Get("cc_rules").Array()

	for i := range result {
		var rule CCRule
		err := json2.Unmarshal([]byte(result[i].Str), &rule)
		if err != nil {
			log.Errorf("[json parse error: %s]", result[i].String())
		}
		//var limiter MyLimiter
		log.Infof("[cc config: %s]", result[i].String())
		config.qps = rule.Qps
		config.qpm = rule.Qpm
		config.qpd = rule.Qpd
		config.headerBlockTime = rule.BlockSeconds
		if rule.BlockSeconds != 0 {
			config.headerBlockTime = rule.BlockSeconds
			config.hasHeaderBlock = true
		} else {
			config.headerBlockTime = 0
			config.hasHeaderBlock = false
		}

		if rule.Header != "" {
			config.headerKey = rule.Header

		}
		//if rule.Cookie != "" {
		//	config.cookieKey = rule.Cookie
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

func CCTest(file string) {
	var rule CCRule
	var config CCConfig
	err := json2.Unmarshal([]byte(file), &rule)
	if err != nil {
		fmt.Printf("[json parse error: %s]", file)
	}
	//var limiter MyLimiter

	config.qps = rule.Qps
	config.qpm = rule.Qpm
	config.qpd = rule.Qpd
	config.headerBlockTime = rule.BlockSeconds
	if rule.BlockSeconds != 0 {
		config.headerBlockTime = rule.BlockSeconds
		config.hasHeaderBlock = true
	} else {
		config.headerBlockTime = 0
		config.hasHeaderBlock = false
	}

	if rule.Header != "" {
		config.headerKey = rule.Header
	}
}
