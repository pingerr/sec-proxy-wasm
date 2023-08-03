package ccfilter

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
	"strings"
	"sync"
	"time"
)

func PluginStart() {
	wrapper.SetCtx(
		"cc-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

var mu sync.Mutex

type CCConfig struct {
	headerKey       string
	cookieKey       string
	headerQps       int64
	headerQpm       int64
	headerQpd       int64
	cookieQps       int64
	cookieQpm       int64
	cookieQpd       int64
	headerBlockTime int64
	cookieBlockTime int64
	hasHeaderBlock  bool
	hasCookieBlock  bool

	headerMap map[string]*MyLimiter
	cookieMap map[string]*MyLimiter
}

type MyLimiter struct {
	qps *rate.Limiter
	qpm *rate.Limiter
	//qpd          rate.Limiter
	hasBlockTime bool
	nextTime     int64
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	results := json.Get("cc_rules").Array()
	//log.Infof("[json]: %s", json.Get("cc_rules").String())
	config.headerMap = make(map[string]*MyLimiter)
	config.cookieMap = make(map[string]*MyLimiter)
	for i := range results {
		curMap := results[i].Map()
		//if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
		//	config.headerBlockTime = headerBlockTime
		//	config.hasHeaderBlock = true
		//}
		if headerKey := curMap["header"].Str; headerKey != "" {
			config.headerKey = headerKey
			//log.Infof("[header config success: %s]", headerKey)
			if qps := curMap["qps"].Int(); qps != 0 {
				config.headerQps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				config.headerQpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				config.headerQpd = qpd
			}
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			config.cookieKey = cookieKey
			//log.Infof("[cookie config success: %s]", cookieKey)
			if qps := curMap["qps"].Int(); qps != 0 {
				config.cookieQps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				config.cookieQpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				config.cookieQpd = qpd
			}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {
	now := time.Now()
	headerValue, _ := proxywasm.GetHttpRequestHeader(config.headerKey)

	mu.Lock()
	defer mu.Unlock()
	if headerValue != "" {
		//log.Infof("[headerValue: %s]", headerValue)
		hLimiter, isOk := config.headerMap[headerValue]
		if !isOk {
			var newHLimiter MyLimiter
			if config.headerQps != 0 {
				newHLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(config.headerQps))
			}
			//if config.headerQpd != 0 {
			//	myLimiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), int(config.headerQpm))
			//}
			//if config.hasHeaderBlock {
			//	myLimiter.hasBlockTime = config.hasHeaderBlock
			//	myLimiter.nextTime = now.UnixMilli()
			//}
			config.headerMap[headerValue] = &newHLimiter
		} else {
			if hLimiter.hasBlockTime && now.UnixMilli() < hLimiter.nextTime {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else if hLimiter.qps != nil && !hLimiter.qps.Allow() {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				//if limiter.hasBlockTime {
				//	limiter.nextTime = now.UnixMilli() + config.headerBlockTime*1000
				//	log.Infof("[block time : %s ms]", config.headerBlockTime*1000)
				//}
			}
		}
	}
	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil {
		return types.ActionContinue
	}
	//log.Infof("[cookies: %s]", cookies)
	uid := strings.Replace(cookies, config.cookieKey+"=", "", -1)
	//if cookieValue, err := proxywasm.GetHttpRequestHeader(config.cookieKey); err != nil {
	//	log.Errorf("[cookie get error, %s]", config.cookieKey)
	if uid != "" {
		//log.Infof("[uid: %s]", uid)
		cLimiter, isOk := config.cookieMap[uid]
		if !isOk {
			var newCLimiter MyLimiter
			if config.cookieQps != 0 {
				newCLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(config.cookieQps))
			}
			//if config.headerQpd != 0 {
			//	myLimiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), int(config.headerQpm))
			//}
			//if config.hasHeaderBlock {
			//	myLimiter.hasBlockTime = config.hasHeaderBlock
			//	myLimiter.nextTime = now.UnixMilli()
			//}
			config.cookieMap[uid] = &newCLimiter
		} else {
			if cLimiter.hasBlockTime && now.UnixMilli() < cLimiter.nextTime {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else if cLimiter.qps != nil && !cLimiter.qps.Allow() {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				//if limiter.hasBlockTime {
				//	limiter.nextTime = now.UnixMilli() + config.headerBlockTime*1000
				//	log.Infof("[block time : %s ms]", config.headerBlockTime*1000)
				//}
			}
		}
	}

	return types.ActionContinue
}

//func CCTest(file string) {
//	var rule CCRule
//	var config CCConfig
//	err := json2.Unmarshal([]byte(file), &rule)
//	if err != nil {
//		fmt.Printf("[json parse error: %s]", file)
//	}
//	//var limiter MyLimiter
//
//	config.qps = rule.Qps
//	config.qpm = rule.Qpm
//	config.qpd = rule.Qpd
//	config.headerBlockTime = rule.BlockSeconds
//	if rule.BlockSeconds != 0 {
//		config.headerBlockTime = rule.BlockSeconds
//		config.hasHeaderBlock = true
//	} else {
//		config.headerBlockTime = 0
//		config.hasHeaderBlock = false
//	}
//
//	if rule.Header != "" {
//		config.headerKey = rule.Header
//	}
//}
