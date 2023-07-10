package wasmplugin

import (
	"errors"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strings"
)

func PluginStart() {
	wrapper.SetCtx(
		"waf-plugin-go",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onHttpRequestBody),
	)
}

type WafConfig struct {
	waf coraza.WAF
	//tx  ctypes.Transaction
}

func parseConfig(json gjson.Result, config *WafConfig, log wrapper.Log) error {
	var secRules []string
	for _, item := range json.Get("secRules").Array() {
		rule := item.String()
		secRules = append(secRules, rule)
	}
	log.Debugf("[rinfx log] %s", strings.Join(secRules, "\n"))
	conf := coraza.NewWAFConfig().WithRootFS(root)
	// error: Failed to load Wasm module due to a missing import: wasi_snapshot_preview1.fd_filestat_get
	// because without fs.go
	waf, err := coraza.NewWAF(conf.WithDirectives(strings.Join(secRules, "\n")))
	//_, _ = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRule REMOTE_ADDR "@rx .*" "id:1,phase:1,deny,status:403"`))
	config.waf = waf
	if err != nil {
		log.Errorf("Failed to create waf conf: %v", err)
		return errors.New("failed to create waf conf")
	}
	//conf.tx = conf.waf.NewTransaction()
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config WafConfig, log wrapper.Log) types.Action {
	ctx.SetContext("interruptionHandled", false)
	ctx.SetContext("processedRequestBody", false)
	ctx.SetContext("processedResponseBody", false)
	ctx.SetContext("tx", config.waf.NewTransaction())

	tx := ctx.GetContext("tx").(ctypes.Transaction)

	// Note the pseudo-header :path includes the query.
	// See https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1
	uri, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		log.Error("Failed to get :path")
		return types.ActionContinue
	}

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.

	if tx.IsRuleEngineOff() {
		log.Infof("[rinfx log] OnHttpRequestHeaders, RuleEngine Off, url = %s", uri)
		return types.ActionContinue
	}
	// OnHttpRequestHeaders does not terminate if IP/Port retrieve goes wrong
	srcIP, srcPort := retrieveAddressInfo(log, "source")
	dstIP, dstPort := retrieveAddressInfo(log, "destination")

	tx.ProcessConnection(srcIP, srcPort, dstIP, dstPort)

	proxywasm.LogInfof("[rinfx log] OnHttpRequestHeaders, RuleEngine On, url = %s", uri)

	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		log.Error("Failed to get :method")
		return types.ActionContinue
	}

	protocol, err := proxywasm.GetProperty([]string{"request", "protocol"})
	if err != nil {
		// TODO(anuraaga): HTTP protocol is commonly required in WAF rules, we should probably
		// fail fast here, but proxytest does not support properties yet.
		protocol = []byte("HTTP/2.0")
	}

	ctx.SetContext("httpProtocol", string(protocol))

	tx.ProcessURI(uri, method, string(protocol))

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		log.Error("Failed to get request headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	// CRS rules tend to expect Host even with HTTP/2
	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err == nil {
		tx.AddRequestHeader("Host", authority)
		tx.SetServerName(parseServerName(log, authority))
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by waf"), -1); err != nil {
			panic(err)
		}
		return handleInterruption(ctx, "http_request_headers", interruption, log)
	}

	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config WafConfig, body []byte, log wrapper.Log) types.Action {
	log.Info("[rinfx log] OnHttpRequestBody")

	if ctx.GetContext("interruptionHandled").(bool) {
		log.Error("OnHttpRequestBody, interruption already handled")
		return types.ActionContinue
	}

	tx := ctx.GetContext("tx").(ctypes.Transaction)

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to request body data if SecRequestBodyAccess is set to false
	//if !tx.IsRequestBodyAccessible() {
	//	log.Info("Skipping request body inspection, SecRequestBodyAccess is off.")
	//	// ProcessRequestBody is still performed for phase 2 rules, checking already populated variables
	//	ctx.SetContext("processedRequestBody", true)
	//	interruption, err := tx.ProcessRequestBody()
	//	if err != nil {
	//		log.Error("Failed to process request body")
	//		return types.ActionContinue
	//	}
	//
	//	if interruption != nil {
	//		return handleInterruption(ctx, "http_request_body", interruption, log)
	//	}
	//
	//	return types.ActionContinue
	//}

	interruption, _, err := tx.WriteRequestBody(body)
	if err != nil {
		log.Error("Failed to write request body")
		return types.ActionContinue
	}

	if interruption != nil {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by waf"), -1); err != nil {
			panic(err)
		}
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}

	ctx.SetContext("processedRequestBody", true)
	interruption, err = tx.ProcessRequestBody()
	if err != nil {
		log.Error("Failed to process request body")
		return types.ActionContinue
	}
	if interruption != nil {
		if err := proxywasm.SendHttpResponse(403, nil, []byte("denied by waf"), -1); err != nil {
			panic(err)
		}
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}

	return types.ActionContinue
}

func onHttpStreamDone(ctx wrapper.HttpContext, config WafConfig, log wrapper.Log) {
	log.Info("[rinfx log] OnHttpStreamDone")

	tx := ctx.GetContext("tx").(ctypes.Transaction)

	if !tx.IsRuleEngineOff() {
		// Responses without body won't call OnHttpResponseBody, but there are rules in the response body
		// phase that still need to be executed. If they haven't been executed yet, now is the time.
		if !ctx.GetContext("processedResponseBody").(bool) {
			ctx.SetContext("processedResponseBody", true)
			_, err := tx.ProcessResponseBody()
			if err != nil {
				log.Error("Failed to process response body")
			}
		}
	}

	tx.ProcessLogging()

	_ = tx.Close()
	log.Info("Finished")
}
