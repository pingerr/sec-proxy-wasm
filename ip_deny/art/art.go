package art

import (
	"bytes"
)

func loadip4(ipstr []byte) (uint32, error) {
	var (
		ip  uint32
		oct uint32
		b   byte
		num byte
	)

	for _, b = range ipstr {
		switch {
		case b == '.':
			num++
			if 0xffffffff-ip < oct {
				return 0, nil
			}
			ip = ip<<8 + oct
			oct = 0
		case b >= '0' && b <= '9':
			oct = oct*10 + uint32(b-'0')
			if oct > 255 {
				return 0, nil
			}
		default:
			return 0, nil
		}
	}
	if num != 3 {
		return 0, nil
	}
	if 0xffffffff-ip < oct {
		return 0, nil
	}
	return ip<<8 + oct, nil
}

func parsecidr4(cidr []byte) (uint32, uint32, error) {
	var mask uint32
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		for _, c := range cidr[p+1:] {
			if c < '0' || c > '9' {
				return 0, 0, nil
			}
			mask = mask*10 + uint32(c-'0')
		}
		mask = 0xffffffff << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = 0xffffffff
	}
	ip, err := loadip4(cidr)
	if err != nil {
		return 0, 0, err
	}
	return ip, mask, nil
}
