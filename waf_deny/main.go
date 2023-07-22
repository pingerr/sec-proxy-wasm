package main

import (
	"waf_deny/denyall"
)

func main() {
	//wasilibs.RegisterRX()
	//wasilibs.RegisterPM()
	//wasilibs.RegisterSQLi()
	//wasilibs.RegisterXSS()
	//
	//_ = pingerPlugins.RegisterPingerTransformations()
	//
	//wasmplugin.PluginStart()
	denyall.PluginStart()
}
