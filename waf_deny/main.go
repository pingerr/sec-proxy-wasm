package main

import (
	wasilibs "github.com/corazawaf/coraza-wasilibs"
	"waf_deny/pingerPlugins"
	"waf_deny/wasmplugin"
)

func main() {
	wasilibs.RegisterRX()
	wasilibs.RegisterPM()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()

	//增加自定义的 base64flatDecode 方法
	_ = pingerPlugins.RegisterPingerTransformations()

	wasmplugin.PluginStart()
}
