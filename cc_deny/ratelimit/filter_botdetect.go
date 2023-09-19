package ratelimit

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func PluginStart() {
	proxywasm.SetVMContext(&vmContext{})
}

const (
	secondNano = 1000 * 1000 * 1000
	minuteNano = 60 * secondNano
	hourNano   = 60 * minuteNano
	dayNano    = 24 * hourNano

	cookiePre = "c:"
	headerPre = "h:"

	maxGetTokenRetry = 10
)

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
		rules []Rule
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	Rule struct {
		isHeader   bool
		isBlockAll bool
		key        string
		qps        int64
		qpm        int64
		qpd        int64
		needBlock  bool
		blockTime  int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		rules: []Rule{},
	}
}

func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID, p: p}
}

func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		return types.OnPluginStartStatusOK
	}
	if err != nil {
		return types.OnPluginStartStatusFailed
	}
	if !gjson.Valid(string(data)) {
		return types.OnPluginStartStatusFailed
	}

	results := gjson.Get(string(data), "cc_rules").Array()

	for i := range results {
		curMap := results[i].Map()
		if curMap["header"].Exists() {
			var rule Rule
			rule.isHeader = true
			rule.key = curMap["header"].String()
			if curMap["qps"].Exists() {
				rule.qps = curMap["qps"].Int()
				if rule.qps == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpm"].Exists() {
				rule.qpm = curMap["qpm"].Int()
				if rule.qpm == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpd"].Exists() {
				rule.qpd = curMap["qpd"].Int()
				if rule.qpd == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["block_seconds"].Exists() {
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
				if rule.blockTime == 0 {
					rule.needBlock = false
				} else {
					rule.needBlock = true
				}
			}
			p.rules = append(p.rules, rule)
		} else if curMap["cookie"].Exists() {
			var rule Rule
			rule.isHeader = false
			rule.key = curMap["cookie"].String()
			if curMap["qps"].Exists() {
				rule.qps = curMap["qps"].Int()
				if rule.qps == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpm"].Exists() {
				rule.qpm = curMap["qpm"].Int()
				if rule.qpm == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpd"].Exists() {
				rule.qpd = curMap["qpd"].Int()
				if rule.qpd == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["block_seconds"].Exists() {
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
				if rule.blockTime == 0 {
					rule.needBlock = false
				} else {
					rule.needBlock = true
				}
			}
			p.rules = append(p.rules, rule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	//bot block

	ua, _ := proxywasm.GetHttpRequestHeader("user-agent")
	if ua != "" {
		re1 := regexp.MustCompile("(?:\\/[A-Za-z0-9\\.]+|) {0,5}([A-Za-z0-9 \\-_\\!\\[\\]:]{0,50}(?:[Aa]rchiver|[Ii]ndexer|[Ss]craper|[Bb]ot|[Ss]pider|[Cc]rawl[a-z]{0,50}))[/ ](\\d+)(?:\\.(\\d+)(?:\\.(\\d+)|)|)")
		re2 := regexp.MustCompile("(?:\\/[A-Za-z0-9\\.]+|) {0,5}([A-Za-z0-9 \\-_\\!\\[\\]:]{0,50}(?:[Aa]rchiver|[Ii]ndexer|[Ss]craper|[Bb]ot|[Ss]pider|[Cc]rawl[a-z]{0,50})) (\\d+)(?:\\.(\\d+)(?:\\.(\\d+)|)|)")
		re3 := regexp.MustCompile("((?:[A-z0-9]{1,50}|[A-z\\-]{1,50} ?|)(?: the |)(?:[Ss][Pp][Ii][Dd][Ee][Rr]|[Ss]crape|[Cc][Rr][Aa][Ww][Ll])[A-z0-9]{0,50})(?:(?:[ /]| v)(\\d+)(?:\\.(\\d+)|)(?:\\.(\\d+)|)|)")
		re4 := regexp.MustCompile("/((?:Ant-)?Nutch|[A-z]+[Bb]ot|[A-z]+[Ss]pider|Axtaris|fetchurl|Isara|ShopSalad|Tailsweep)[ \\-](\\d+)(?:\\.(\\d+)(?:\\.(\\d+))?)?")
		re5 := regexp.MustCompile("\\b(008|Altresium|Argus|BaiduMobaider|BoardReader|DNSGroup|DataparkSearch|EDI|Goodzer|Grub|INGRID|Infohelfer|LinkedInBot|LOOQ|Nutch|OgScrper|PathDefender|Peew|PostPost|Steeler|Twitterbot|VSE|WebCrunch|WebZIP|Y!J-BR[A-Z]|YahooSeeker|envolk|sproose|wminer)/(\\d+)(?:\\.(\\d+)|)(?:\\.(\\d+)|)")
		re6 := regexp.MustCompile("(CSimpleSpider|Cityreview Robot|CrawlDaddy|CrawlFire|Finderbots|Index crawler|Job Roboter|KiwiStatus Spider|Lijit Crawler|QuerySeekerSpider|ScollSpider|Trends Crawler|USyd-NLP-Spider|SiteCat Webbot|BotName\\/\\$BotVersion|123metaspider-Bot|1470\\.net crawler|50\\.nu|8bo Crawler Bot|Aboundex|Accoona-[A-z]{1,30}-Agent|AdsBot-Google(?:-[a-z]{1,30}|)|altavista|AppEngine-Google|archive.{0,30}\\.org_bot|archiver|Ask Jeeves|[Bb]ai[Dd]u[Ss]pider(?:-[A-Za-z]{1,30})(?:-[A-Za-z]{1,30}|)|bingbot|BingPreview|blitzbot|BlogBridge|Bloglovin|BoardReader Blog Indexer|BoardReader Favicon Fetcher|boitho.com-dc|BotSeer|BUbiNG|\\b\\w{0,30}favicon\\w{0,30}\\b|\\bYeti(?:-[a-z]{1,30}|)|Catchpoint(?: bot|)|[Cc]harlotte|Checklinks|clumboot|Comodo HTTP\\(S\\) Crawler|Comodo-Webinspector-Crawler|ConveraCrawler|CRAWL-E|CrawlConvera|Daumoa(?:-feedfetcher|)|Feed Seeker Bot|Feedbin|findlinks|Flamingo_SearchEngine|FollowSite Bot|furlbot|Genieo|gigabot|GomezAgent|gonzo1|(?:[a-zA-Z]{1,30}-|)Googlebot(?:-[a-zA-Z]{1,30}|)|Google SketchUp|grub-client|gsa-crawler|heritrix|HiddenMarket|holmes|HooWWWer|htdig|ia_archiver|ICC-Crawler|Icarus6j|ichiro(?:/mobile|)|IconSurf|IlTrovatore(?:-Setaccio|)|InfuzApp|Innovazion Crawler|InternetArchive|IP2[a-z]{1,30}Bot|jbot\\b|KaloogaBot|Kraken|Kurzor|larbin|LEIA|LesnikBot|Linguee Bot|LinkAider|LinkedInBot|Lite Bot|Llaut|lycos|Mail\\.RU_Bot|masscan|masidani_bot|Mediapartners-Google|Microsoft .{0,30} Bot|mogimogi|mozDex|MJ12bot|msnbot(?:-media {0,2}|)|msrbot|Mtps Feed Aggregation System|netresearch|Netvibes|NewsGator[^/]{0,30}|^NING|Nutch[^/]{0,30}|Nymesis|ObjectsSearch|OgScrper|Orbiter|OOZBOT|PagePeeker|PagesInventory|PaxleFramework|Peeplo Screenshot Bot|PlantyNet_WebRobot|Pompos|Qwantify|Read%20Later|Reaper|RedCarpet|Retreiver|Riddler|Rival IQ|scooter|Scrapy|Scrubby|searchsight|seekbot|semanticdiscovery|SemrushBot|Simpy|SimplePie|SEOstats|SimpleRSS|SiteCon|Slackbot-LinkExpanding|Slack-ImgProxy|Slurp|snappy|Speedy Spider|Squrl Java|Stringer|TheUsefulbot|ThumbShotsBot|Thumbshots\\.ru|Tiny Tiny RSS|Twitterbot|WhatsApp|URL2PNG|Vagabondo|VoilaBot|^vortex|Votay bot|^voyager|WASALive.Bot|Web-sniffer|WebThumb|WeSEE:[A-z]{1,30}|WhatWeb|WIRE|WordPress|Wotbox|www\\.almaden\\.ibm\\.com|Xenu(?:.s|) Link Sleuth|Xerka [A-z]{1,30}Bot|yacy(?:bot|)|YahooSeeker|Yahoo! Slurp|Yandex\\w{1,30}|YodaoBot(?:-[A-z]{1,30}|)|YottaaMonitor|Yowedo|^Zao|^Zao-Crawler|ZeBot_www\\.ze\\.bz|ZooShot|ZyBorg)(?:[ /]v?(\\d+)(?:\\.(\\d+)(?:\\.(\\d+)|)|)|)")
		if re1.Match([]byte(ua)) || re2.Match([]byte(ua)) || re3.Match([]byte(ua)) || re4.Match([]byte(ua)) || re5.Match([]byte(ua)) || re6.Match([]byte(ua)) {
			_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			return types.ActionContinue
		}
	}

	var md5Str string
	for _, rule := range ctx.p.rules {
		if rule.isHeader {
			headerValue, err := proxywasm.GetHttpRequestHeader(rule.key)
			if err == nil && headerValue != "" {

				if rule.isBlockAll {
					//isBlock = true
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

				hLimitKeyBuf := bytes.NewBufferString(headerPre)
				hLimitKeyBuf.WriteString(rule.key)
				hLimitKeyBuf.WriteString(":")
				hLimitKeyBuf.WriteString(headerValue)

				sum := md5.Sum(hLimitKeyBuf.Bytes())
				md5Str = hex.EncodeToString(sum[:])

				if !getEntry(md5Str, rule) {
					//isBlock = true
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

			}
		} else {
			cookies, err := proxywasm.GetHttpRequestHeader("cookie")
			if err == nil && cookies != "" {
				cSub := bytes.NewBufferString(rule.key)
				cSub.WriteString("=")
				if strings.HasPrefix(cookies, cSub.String()) {
					cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
					if cookieValue != "" {

						if rule.isBlockAll {
							//isBlock = true
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
							return types.ActionContinue
						}

						cLimitKeyBuf := bytes.NewBufferString(cookiePre)
						cLimitKeyBuf.WriteString(rule.key)
						cLimitKeyBuf.WriteString(":")
						cLimitKeyBuf.WriteString(cookieValue)

						sum := md5.Sum(cLimitKeyBuf.Bytes())
						md5Str = hex.EncodeToString(sum[:])

						if !getEntry(md5Str, rule) {
							//isBlock = true
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
							return types.ActionContinue
						}
					}
				}
			}
		}
	}
	//if isBlock {
	//	_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//}

	return types.ActionContinue
}

// data=[count:sRefillTime:mRefillTime:dRefillTime:isBlock:lastBlockTime]
func getEntry(shareDataKey string, rule Rule) bool {
	var data []byte
	var cas uint32
	var sRequestCount int64
	var mRequestCount int64
	var dRequestCount int64
	var sRefillTime int64
	var mRefillTime int64
	var dRefillTime int64
	var isBlock int
	var lastBlockTime int64

	var err error

	for i := 0; i < maxGetTokenRetry; i++ {
		now := time.Now().UnixNano()
		isAllow := true
		data, cas, err = proxywasm.GetSharedData(shareDataKey)

		if err != nil && err != types.ErrorStatusNotFound {
			continue
		}

		if err != nil && err == types.ErrorStatusNotFound {
			sRequestCount = 1
			mRequestCount = 1
			dRequestCount = 1
			sRefillTime = now
			mRefillTime = now
			dRefillTime = now
			isBlock = 0
			lastBlockTime = 0
		}

		if err == nil {
			// Tokenize the string on :
			parts := strings.Split(string(data), ":")
			sRequestCount, _ = strconv.ParseInt(parts[0], 0, 64)
			mRequestCount, _ = strconv.ParseInt(parts[1], 0, 64)
			dRequestCount, _ = strconv.ParseInt(parts[2], 0, 64)
			sRefillTime, _ = strconv.ParseInt(parts[3], 0, 64)
			mRefillTime, _ = strconv.ParseInt(parts[4], 0, 64)
			dRefillTime, _ = strconv.ParseInt(parts[5], 0, 64)
			isBlock, _ = strconv.Atoi(parts[6])
			lastBlockTime, _ = strconv.ParseInt(parts[7], 0, 64)

			if rule.needBlock {
				if isBlock == 1 {
					if now-lastBlockTime > rule.blockTime {
						isBlock = 0

						if rule.qps != 0 && now-sRefillTime > secondNano {
							sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
							sRequestCount = 0
						}
						if rule.qpm != 0 && now-mRefillTime > minuteNano {
							mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
							mRequestCount = 0
						}
						if rule.qpd != 0 && now-dRefillTime > dayNano {
							dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
							dRequestCount = 0
						}

						sRequestCount++
						mRequestCount++
						dRequestCount++

						if (rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
							(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
							(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) {
							lastBlockTime = now
							isBlock = 1
							isAllow = false
						}

					} else {
						isAllow = false
					}
				} else {
					if rule.qps != 0 && now-sRefillTime > secondNano {
						sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
						sRequestCount = 0
					}
					if rule.qpm != 0 && now-mRefillTime > minuteNano {
						mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
						mRequestCount = 0
					}
					if rule.qpd != 0 && now-dRefillTime > dayNano {
						dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
						dRequestCount = 0
					}

					sRequestCount++
					mRequestCount++
					dRequestCount++

					if (rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
						(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
						(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) {
						lastBlockTime = now
						isBlock = 1
						isAllow = false
					}
				}
			} else {
				if rule.qps != 0 && now-sRefillTime > secondNano {
					sRequestCount = 0
					sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
				}
				if rule.qpm != 0 && now-mRefillTime > minuteNano {
					mRequestCount = 0
					mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
				}
				if rule.qpd != 0 && now-dRefillTime > dayNano {
					dRequestCount = 0
					dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
				}

				sRequestCount++
				mRequestCount++
				dRequestCount++

				if (rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
					(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
					(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) {
					isAllow = false
				}
			}
		}

		newData := bytes.NewBufferString(strconv.FormatInt(sRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(mRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(dRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(sRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(mRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(dRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(int64(isBlock), 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(lastBlockTime, 10))

		err := proxywasm.SetSharedData(shareDataKey, newData.Bytes(), cas)
		if err != nil {
			continue
		}

		return isAllow
	}
	return true
}
