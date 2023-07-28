package main

import (
	"ip_deny/ipfilter"
)

//"ip_deny/cuckoofilter"
//"ip_deny/ipfilter"

func main() {
	ipfilter.FilterStart()
	//cuckoofilter.FilterStart()
	//cidranger.FilterStart()
	//radixTree.FilterStart()
}
