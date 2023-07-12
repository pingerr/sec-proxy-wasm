package main

import (
	wasilibs "github.com/corazawaf/coraza-wasilibs"
	"waf_deny/wasmplugin"
)

func main() {
	wasilibs.RegisterRX()
	//plugins.RegisterOperator("rx", newRX)
	wasilibs.RegisterPM()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
	wasmplugin.PluginStart()
}
