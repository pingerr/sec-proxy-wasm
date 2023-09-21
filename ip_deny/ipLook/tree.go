package ipLook

import (
	"encoding/binary"
	"net"
)

// bitsLen 常数表示每个节点存储bit子串的长度，必须是2的指数次幂,可根据subnet前缀长度重新指定
// 当 bitsLen 为 4 时，最大跳数(树的深度)将为32 / bitsLen.
const bitsLen = 4

// SID SID表示对应节点的状态，每一位表示1种状态。
// uint8 表示可以存储8个状态。
// ip 黑名单场景，只用了1和0两个状态
type SID uint8

type Tree struct {
	root *treeNode
}

// treeNode bit树节点
// 如果每个节点保存4个bit（bitsLen=4）的信息，即"0 or 1, 0 or 1, 0 or 1, 0 or 1",则有1<<4= 16种排列组合
type treeNode struct {
	srvs [1 << bitsLen]SID
	ptrs [1 << bitsLen]*treeNode
}

// New 建立新的IP subnet tree，仅实现IPv4。
func New() *Tree {
	tree := &Tree{&treeNode{}}
	return tree
}

// Add 将IP subnet添加到树中
// 状态应该只包含一个真正的位（即使使用多个位也可以正常工作）
// ipnet.IP必须长度为4（IPv4）
func (tree *Tree) Add(service SID, ipnet net.IPNet) {
	node := tree.root

	prefixLen, _ := ipnet.Mask.Size() //比如24
	curLen := bitsLen                 //4
	for i := 0; i < 32/bitsLen; i++ { //i范围[0,8)
		if curLen >= prefixLen {
			//当前节点为叶子结点，填充状态值
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
			node.ptrs[ind] = &treeNode{}
			node = node.ptrs[ind]
		}
		curLen += bitsLen
	}
}

// Get 获得IPv4对应的SID值，IPv4必须为长度为4
func (tree *Tree) Get(ipv4 []byte) SID {
	var ans SID
	cur := tree.root

	for i := 0; i < 32/bitsLen; i++ {
		ind := getSubstring(ipv4, uint8(i))
		ans = ans | cur.srvs[ind] //非叶子节点的ans都为0
		if cur = cur.ptrs[ind]; cur == nil {
			break
		}
	}

	return ans
}

// getSubstring 获取在区间 [index * bitsLen, index * bitsLen + bitsLen) 内的bit子串的10进制值
// 例如. 11101111111111111111111111111111, 区间[0, 4)，子串为1110，结果为 14
func getSubstring(ipv4 []byte, index uint8) uint32 {
	var ans = binary.BigEndian.Uint32(ipv4)
	ans = ans << (bitsLen * index)
	ans = ans >> (32 - bitsLen)
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
