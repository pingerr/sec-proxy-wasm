package main

import (
	"ip_deny/ipLook"
	"ip_deny/myRadixTree"
)

func main() {
	myRadixTree.FilterStart()
	ipLook.FilterStart()
}
