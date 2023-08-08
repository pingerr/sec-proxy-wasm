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
	//ipArr = append(ipArr, "135.135.135.135")
	//for n := 0; n < b.N; n++ {
	//t := myRadixTree.NewTree()
	//for i := range ipArr {
	//	_ = t.SetCIDRb([]byte(ipArr[i]), 1)
	//}
	//BenchmarkIp-4               2023            582941 ns/op          534854 B/op         13 allocs/op
	//BenchmarkIp-4               1944            606920 ns/op          534856 B/op         13 allocs/op
	//BenchmarkIp-4               1954            550793 ns/op          534855 B/op         13 allocs/op
	//BenchmarkIp-4               1963            593881 ns/op          534855 B/op         13 allocs/op
	//BenchmarkIp-4               1837            583084 ns/op          534856 B/op         13 allocs/op
	// mem
	//BenchmarkIp-4               2991            375954 ns/op          534848 B/op         13 allocs/op
	//BenchmarkIp-4               3349            383180 ns/op          534845 B/op         13 allocs/op
	//BenchmarkIp-4               3925            404930 ns/op          534844 B/op         13 allocs/op
	//BenchmarkIp-4               2799            386333 ns/op          534848 B/op         13 allocs/op
	//BenchmarkIp-4               2930            381192 ns/op          534848 B/op         13 allocs/op

	//for i := range ipArr {
	//	_, _ = t.FindCIDRb([]byte(ipArr[i]))
	//	//found, _ := t.FindIpv4([]byte(ipArr[i]))
	//	//fmt.Println(found)
	//}
	//goos: linux
	//goarch: amd64
	//pkg: ip_deny/test
	//cpu: Intel(R) Xeon(R) Gold 6278C CPU @ 2.60GHz
	//BenchmarkIp-2              10000            118533 ns/op              57 B/op          0 allocs/op
	//BenchmarkIp-2               9862            116700 ns/op              58 B/op          0 allocs/op
	//BenchmarkIp-2              10000            118475 ns/op              57 B/op          0 allocs/op
	//BenchmarkIp-2               9795            117470 ns/op              59 B/op          0 allocs/op
	//BenchmarkIp-2               9870            118121 ns/op              58 B/op          0 allocs/op
	// FindIpv4
	//goos: linux
	//goarch: amd64
	//pkg: ip_deny/test
	//cpu: Intel(R) Xeon(R) Gold 6278C CPU @ 2.60GHz
	//BenchmarkIp-2              10000            122281 ns/op              57 B/op          0 allocs/op
	//BenchmarkIp-2              10000            107754 ns/op              57 B/op          0 allocs/op
	//BenchmarkIp-2              10000            106516 ns/op              57 B/op          0 allocs/op
	//BenchmarkIp-2              11198            107759 ns/op              51 B/op          0 allocs/op
	//BenchmarkIp-2              10000            106136 ns/op              57 B/op          0 allocs/op
	//}
	//t := myRadixTree.NewTree()
	//_ = t.SetCIDRb([]byte("1.1.1.1/24"), 1)
	//_, _ = t.FindCIDRb([]byte("1.1.1.2"))

	var id ipLook.SID = 1
	tree := ipLook.New()
	for _, cidr := range ipArr {
		if index := bytes.IndexByte([]byte(cidr), '/'); index < 0 {
			cidr = cidr + "/24"
		}
		_, ipNet, _ := net.ParseCIDR(cidr)
		tree.Add(id, *ipNet)
	}
	//ipArr = append(ipArr, "135.135.135.135")
	for n := 0; n < b.N; n++ {
		//	var id ipLook.SID = 1
		//	tree := ipLook.New()
		//	for i, _ := range ipArr {
		//		cidrBuf := bytes.NewBufferString(ipArr[i])
		//		if index := bytes.IndexByte(cidrBuf.Bytes(), '/'); index < 0 {
		//			cidrBuf.WriteString("/24")
		//		}
		//		_, ipNet, _ := net.ParseCIDR(cidrBuf.String())
		//		tree.Add(id, *ipNet)
		//goos: windows
		//goarch: amd64
		//pkg: ip_deny/test
		//cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz
		//BenchmarkIp-4               2298            490945 ns/op          607967 B/op       5406 allocs/op
		//BenchmarkIp-4               2302            466568 ns/op          607966 B/op       5406 allocs/op
		//BenchmarkIp-4               2358            517260 ns/op          607965 B/op       5406 allocs/op
		//BenchmarkIp-4               2013            522196 ns/op          607969 B/op       5406 allocs/op
		//BenchmarkIp-4               2200            489812 ns/op          607967 B/op       5406 allocs/op
		//SID uint8
		//BenchmarkIp-4               2702            414179 ns/op          368171 B/op       5406 allocs/op
		//BenchmarkIp-4               2976            444895 ns/op          368169 B/op       5406 allocs/op
		//BenchmarkIp-4               2407            679107 ns/op          368172 B/op       5406 allocs/op
		//BenchmarkIp-4               2814            415113 ns/op          368169 B/op       5406 allocs/op
		//BenchmarkIp-4               2810            409978 ns/op          368169 B/op       5406 allocs/op
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
			//fmt.Println(tree.Get(ipLook.ParseIPv4(ipArr[i])))
		}
	}

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
