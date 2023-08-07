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

	//t := myRadixTree.NewTree()
	//for i := range ipArr {
	//	_ = t.SetCIDRb([]byte(ipArr[i]), 1)
	//}
	//for n := 0; n < b.N; n++ {
	//	t := myRadixTree.NewTree()
	//	for i := range ipArr {
	//		_ = t.SetCIDRb([]byte(ipArr[i]), 1)
	//	}
	//
	//	//BenchmarkIp-4               2023            582941 ns/op          534854 B/op         13 allocs/op
	//	//BenchmarkIp-4               1944            606920 ns/op          534856 B/op         13 allocs/op
	//	//BenchmarkIp-4               1954            550793 ns/op          534855 B/op         13 allocs/op
	//	//BenchmarkIp-4               1963            593881 ns/op          534855 B/op         13 allocs/op
	//	//BenchmarkIp-4               1837            583084 ns/op          534856 B/op         13 allocs/op

	//	for i := range ipArr {
	//		_, _ = t.FindCIDRb([]byte(ipArr[i]))
	//		//fmt.Println(found)
	//	}
	//	//goos: windows
	//	//goarch: amd64
	//	//pkg: ip_deny/test
	//	//cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz
	//	//BenchmarkIp-4               7690            140662 ns/op              75 B/op          0 allocs/op
	//	//BenchmarkIp-4              10000            152221 ns/op              57 B/op          0 allocs/op
	//	//BenchmarkIp-4               7460            143445 ns/op              77 B/op          0 allocs/op
	//	//BenchmarkIp-4              10000            143369 ns/op              57 B/op          0 allocs/op
	//	//BenchmarkIp-4               8318            147110 ns/op              69 B/op          0 allocs/op

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
	for n := 0; n < b.N; n++ {
		//var id ipLook.SID = 1
		//tree := ipLook.New()
		//for i, _ := range ipArr {
		//	cidrBuf := bytes.NewBufferString(ipArr[i])
		//	if index := bytes.IndexByte(cidrBuf.Bytes(), '/'); index < 0 {
		//		cidrBuf.WriteString("/24")
		//	}
		//	_, ipNet, _ := net.ParseCIDR(cidrBuf.String())
		//	tree.Add(id, *ipNet)
		//	//goos: windows
		//	//goarch: amd64
		//	//pkg: ip_deny/test
		//	//cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz
		//	//BenchmarkIp-4               2298            490945 ns/op          607967 B/op       5406 allocs/op
		//	//BenchmarkIp-4               2302            466568 ns/op          607966 B/op       5406 allocs/op
		//	//BenchmarkIp-4               2358            517260 ns/op          607965 B/op       5406 allocs/op
		//	//BenchmarkIp-4               2013            522196 ns/op          607969 B/op       5406 allocs/op
		//	//BenchmarkIp-4               2200            489812 ns/op          607967 B/op       5406 allocs/op
		//}
		for i := range ipArr {
			//goos: windows
			//goarch: amd64
			//pkg: ip_deny/test
			//cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz
			//BenchmarkIp-4              14262             78307 ns/op            2657 B/op        653 allocs/op
			//BenchmarkIp-4              15202             81512 ns/op            2654 B/op        653 allocs/op
			//BenchmarkIp-4              15096             77823 ns/op            2655 B/op        653 allocs/op
			//BenchmarkIp-4              15492             78030 ns/op            2654 B/op        653 allocs/op
			//BenchmarkIp-4              15279             79110 ns/op            2654 B/op        653 allocs/op
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
