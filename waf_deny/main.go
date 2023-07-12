package main

import (
	wasilibs "github.com/corazawaf/coraza-wasilibs"
	"waf_deny/wasmplugin"
)

func main() {
	wasilibs.RegisterRX()
	wasilibs.RegisterPM()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
	wasmplugin.PluginStart()
}
