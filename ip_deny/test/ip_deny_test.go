package test

import (
	"bufio"
	"fmt"
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
	//	myRadixTree.RadixTest(ipArr, t) //BenchmarkIp-4               2241            527007 ns/op          639045 B/op         13 allocs/op
	//	// // BenchmarkIp-4               9032            124534 ns/op              75 B/op          0 allocs/op
	//	//for i := range ipArr {
	//	//	_, _ = t.FindCIDRb([]byte(ipArr[i]))
	//	//	//fmt.Println(found)
	//	//}
	//}

	//var trie ipTrie.TrieNode
	//trie.Insert(1, ipArr)
	//for n := 0; n < b.N; n++ {
	//	ipTrie.Test(ipArr, trie)
	//	//for i := range ipArr {
	//	//	trie.Lookup(net.ParseIP(ipArr[i])) //BenchmarkIp-4               4561            238057 ns/op           10579 B/op        657 allocs/op
	//	//	//fmt.Println()
	//	//}
	//}
}

//func BenchmarkFlash(b *testing.B) {
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
//
//	fltrie1 := fltrie.New()
//	for _, cidr := range ipArr {
//		if index := bytes.IndexByte([]byte(cidr), '/'); index < 0 {
//			cidr = cidr + "/32"
//		}
//		var r string
//		r, _ = net.ParseNet(cidr)
//
//		fltrie1.Add(r, "A")
//
//	}
//
//	for i := 0; i < b.N; i++ {
//		for i := range ipArr {
//			_ = fltrie1.Lookup(net.ParseIP(ipArr[i]))
//			//fmt.Println(s)
//		}
//	}
//}

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
