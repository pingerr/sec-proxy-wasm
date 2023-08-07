package test

import (
	"bufio"
	"bytes"
	"fmt"
	"ip_deny/ipLook"
	"net"
	"os"
	"testing"
)

func BenchmarkIp(b *testing.B) {

	f, err := os.Open("./cidr")
	if err != nil {
		fmt.Println("read file fail")
	}
	defer f.Close()

	buf := bufio.NewScanner(f)
	var ipArr []string
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		ipArr = append(ipArr, line)
	}

	//t := myRadixTree.NewTree(0)
	//for i := range ipArr {
	//	_ = t.SetCIDRb([]byte(ipArr[i]), 1)
	//}
	//for n := 0; n < b.N; n++ {
	//	//cidranger.CidrangerTest(ipArr) // BenchmarkIp-4                302           3414727 ns/op          801432 B/op      43729 allocs/op
	//	for i := range ipArr {
	//		_, _ = t.FindCIDRb([]byte(ipArr[i]))
	//		//fmt.Println(found)
	//	}
	//	//goos: windows
	//	//goarch: amd64
	//	//pkg: ip_deny/test
	//	//cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz
	//	//BenchmarkIp-4               7030            164570 ns/op              97 B/op          0 allocs/op
	//	//BenchmarkIp-4              10000            151737 ns/op              68 B/op          0 allocs/op
	//	//BenchmarkIp-4               7072            181991 ns/op              96 B/op          0 allocs/op
	//	//BenchmarkIp-4              10000            152848 ns/op              68 B/op          0 allocs/op
	//	//BenchmarkIp-4               7762            154598 ns/op              88 B/op          0 allocs/op
	//	//for i := range ipArr {
	//	//	_, _ = t.FindCIDRb([]byte(ipArr[i]))
	//	//	//fmt.Println(found)
	//	//}
	//}

	var id ipLook.SID = 1
	tree := ipLook.New()
	for _, cidr := range ipArr {
		if index := bytes.IndexByte([]byte(cidr), '/'); index < 0 {
			cidr = cidr + "/24"
		}
		//fmt.Println(cidr)
		_, ipNet, err := net.ParseCIDR(cidr)
		//ip := net.ParseIP(cidr).To4()
		//ip.To4()
		if err != nil {
			fmt.Println(err)
		}

		tree.Add(id, *ipNet)
	}

	//ipArr = append(ipArr, "130.130.130.130")
	for n := 0; n < b.N; n++ {
		for i := range ipArr {
			//BenchmarkIp-4              10000            119869 ns/op           10513 B/op        653 allocs/op
			// BenchmarkIp-4              12860             96100 ns/op            2662 B/op        653 allocs/op
			//fmt.Println(tree.Get(net.ParseIP(ipArr[i])[12:16]) == 1)
			_ = tree.Get(ipLook.ParseIPv4(ipArr[i])) == 1
		}
	}

	//_, ipNet, err := net.ParseCIDR("1.1.1.1/24")
	//var id ipLook.SID = 1
	//tree := ipLook.New()
	//tree.Add(id, *ipNet)
	//_ = tree.Get(net.ParseIP("1.1.1.2")[12:16]) == 1
}

// go test -benchmem  -bench='Ip' . -count=5

//func TestHs(t *testing.T) {
//	f, err := os.Open("./cidr")
//	if err != nil {
//		fmt.Println("read file fail")
//	}
//	defer f.Close()
//
//	buf := bufio.NewScanner(f)
//	var ipArr []string
//	for {
//		if !buf.Scan() {
//			break
//		}
//		line := buf.Text()
//		ipArr = append(ipArr, line)
//	}
//	cidranger.HsTest(ipArr)
//}

//go test -bench='Ip' -benchmem .
