package ipLookTest

import (
	"encoding/binary"
	"net"
)

// bitslen contstant must be a power of 2. It indicates how much space will be taken by a tree and maximum number of hops (treenode accesses).
// When bitslen is 4, the maximum number of hops will be 32 / bitslen and one node takes 1<< bitslen * (sizeof SID and *treenode).
// So current constant (4) will make maximum 8 hops and every node consumes 256 bytes.
const bitslen = 4

// SID type contains a list of corresponding service indexes.
// Every nth bit indicates nth service. So 0x1 stores (0),
// 0x2 stores (1), 0x3 stores (0, 1) services and etc.
// So you can handle up to 64 services.
// 0 indicates that there are no service.
// Example: service has index 6, then its SID representation will be 1<<6
// SID类型包含对应服务索引的列表。
// 每个第n位表示第n个服务。因此，0x1存储(0)，
// 0x2存储(1)，0x3存储(0,1)服务，以此类推。
// 因此，您可以处理多达64个服务。
// 0表示没有服务。
// 例如：服务的索引为6，则其SID表示将是1<<6。
type SID uint8

type Tree struct {
	root *treenode
}

type treenode struct {
	srvs [1 << bitslen]SID
	ptrs [1 << bitslen]*treenode
}

// New creates new IP subnet tree. It only works with IP v4
func New() *Tree {
	tree := &Tree{&treenode{}}
	return tree
}

// Add adds ip subnet to the tree.
// service should contain only one true bit (anyway it works well with multiple bits).
// ipnet.IP must be of the length 4 (IP v4).
// It is up to you to handle this.
// This method does not compress subnets - if you put 1.1.1.1/24 and 1.1.1.1/23
// of the same service, it will hold both subnets.
// 服务应该只包含一个真正的位（但是多个位也可以正常工作）。
// ipnet.IP 必须是长度为4（IP v4）。
// 处理这个问题由你自己决定。
// 如果你将1.1.1.1/24和1.1.1.1/23放在同一个服务中，这个方法不会压缩子网，它将保留两个子网。"
func (tree *Tree) Add(service SID, ipnet net.IPNet) {
	node := tree.root

	prefixLen, _ := ipnet.Mask.Size() //24
	curLen := bitslen                 //4
	for i := 0; i < 32/bitslen; i++ { //i<8
		if curLen >= prefixLen {

			start := getSubstring(ipnet.IP, uint8(i))
			end := start + (1 << uint(curLen-prefixLen)) - 1

			for j := start; j <= end; j++ {
				node.srvs[j] = node.srvs[j] | service
			}
			break
		}

		ind := getSubstring(ipnet.IP, uint8(i))
		if node.ptrs[ind] != nil {
			node = node.ptrs[ind]
		} else {
			node.ptrs[ind] = &treenode{}
			node = node.ptrs[ind]
		}
		curLen += bitslen
	}
}

// Get returns SID which corresponds to this ip v4
// ipv4 must be of length 4 and it is up to you to
// handle this.
func (tree *Tree) Get(ipv4 []byte) SID {
	var ans SID
	cur := tree.root

	for i := 0; i < 32/bitslen; i++ {
		ind := getSubstring(ipv4, uint8(i))
		ans = ans | cur.srvs[ind]
		if cur = cur.ptrs[ind]; cur == nil {
			break
		}
	}

	return ans
}

// getSubstring is helper function that returns substring of bits placed in range [index * bitslen, index * bitslen + bitslen)
// getSubstring是一个辅助函数，它返回位于范围[index * bitslen，index * bitslen + bitslen]中的bits substring。
func getSubstring(ipv4 []byte, index uint8) uint32 {
	var ans = binary.BigEndian.Uint32(ipv4)
	ans = ans << (bitslen * index)
	ans = ans >> (32 - bitslen)
	return ans
}

const IPv4len = 4
const big = 0xFFFFFF

func ParseIPv4(s string) []byte {
	var p = make([]byte, 4)
	for i := 0; i < IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return nil
		}
		if c > 1 && s[0] == '0' {
			// Reject non-zero components with leading zeroes.
			return nil
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return nil
	}
	return p
}

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}
