package main

import (
	"cc_deny/ratelimit"
	_ "github.com/wasilibs/nottinygc"
)

func main() {
	ratelimit.PluginStart()
}

//export sched_yield
func sched_yield() int32 {
	return 0
}
