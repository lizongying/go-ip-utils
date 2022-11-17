package iputils

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// IntToIp4 example 2148409344 -> 128.14.32.0
func IntToIp4(i int) (s string) {
	ips := []string{fmt.Sprintf("%d", i&0xff)}
	for k := 0; k < 3; k++ {
		i >>= 8
		ips = append([]string{fmt.Sprintf("%d", i&0xff)}, ips...)
	}
	s = strings.Join(ips, ".")
	return
}

// Ip4ToInt example 128.14.32.0 -> 2148409344
func Ip4ToInt(s string) (i int) {
	for k, a := range strings.Split(s, ".") {
		ai, _ := strconv.Atoi(a)
		i += ai << ((3 - k) * 8)
	}
	return
}

// BytesToIp4 example [128 14 32 0] -> 128.14.32.0
func BytesToIp4(bs []byte) (s string) {
	var ips []string
	for _, i := range bs {
		ips = append(ips, fmt.Sprintf("%d", i))
	}
	s = strings.Join(ips, ".")
	return
}

// BytesToIp6 example [254 128 0 0 9 130 42 92 0 0 0 0 0 0 255 255] -> fe80:0:982:2a5c:0:0:0:ffff
func BytesToIp6(bs []byte) (s string) {
	var ips []string
	for i := 0; i < len(bs); i += 2 {
		ai := binary.BigEndian.Uint16(bs[i : i+2])
		ips = append(ips, fmt.Sprintf("%x", ai))
	}
	s = strings.Join(ips, ":")
	return
}

// Ip4ToBytes example 128.14.32.0 -> [128 14 32 0]
func Ip4ToBytes(s string) (bs []byte) {
	for _, a := range strings.Split(s, ".") {
		ai, _ := strconv.Atoi(a)
		bs = append(bs, byte(ai))
	}
	return
}

// Ip6ToBytes example fe80:0:982:2a5c:0:0:0:ffff -> [254 128 0 0 9 130 42 92 0 0 0 0 0 0 255 255]
func Ip6ToBytes(s string) (bs []byte) {
	for _, a := range strings.Split(s, ":") {
		ai, _ := strconv.ParseInt(a, 16, 0)
		i := uint16(ai)
		bs = binary.BigEndian.AppendUint16(bs, i)
	}
	return
}

// IntToBytes example 2148409344 -> [128 14 32 0]
func IntToBytes(n int) []byte {
	data := uint32(n)
	byteBuffer := bytes.NewBuffer([]byte{})
	_ = binary.Write(byteBuffer, binary.BigEndian, data)
	return byteBuffer.Bytes()
}

// BytesToInt example [128 14 32 0] -> 2148409344
func BytesToInt(bs []byte) (i int) {
	byteBuffer := bytes.NewBuffer(bs)
	var data uint32
	_ = binary.Read(byteBuffer, binary.BigEndian, &data)
	i = int(data)
	return
}

// Cidr4ToIps example 128.14.35.7/20 -> [128.14.32.0 ~ 128.14.47.255]
func Cidr4ToIps(s string) (ips []string, err error) {
	reIpv4 := regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,3})$`)
	r := reIpv4.FindStringSubmatch(s)
	if len(r) != 6 {
		err = errors.New("format err")
		return
	}
	d, _ := strconv.Atoi(r[5])
	if d > 32 {
		err = errors.New("greater than 32")
		return
	}
	var first []int
	var last []int
	for _, a := range r[1:5] {
		i, _ := strconv.Atoi(a)
		if i > 0xff {
			err = errors.New("greater than 255")
			break
		}
		var m int
		if d >= 8 {
			m = 0xff
		} else if 0 < d && d < 8 {
			m = 0xff << (8 - d) & 0xff
		} else {
			m = 0
		}

		f := i & m
		first = append(first, f)

		l := f + (m ^ 0xff)
		last = append(last, l)
		d -= 8
	}

	if len(first) < 4 {
		err = errors.New("less than 4")
		return
	}

	for v0 := first[0]; v0 <= last[0]; v0++ {
		for v1 := first[1]; v1 <= last[1]; v1++ {
			for v2 := first[2]; v2 <= last[2]; v2++ {
				for v3 := first[3]; v3 <= last[3]; v3++ {
					ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", v0, v1, v2, v3))
				}
			}
		}
	}
	return
}

// Cidr4ToIpsClean example 128.14.35.7/20 -> [128.14.32.1 ~ 128.14.47.254]
func Cidr4ToIpsClean(s string) (ips []string, err error) {
	ipsRaw, err := Cidr4ToIps(s)
	if err != nil {
		return
	}

	for _, v := range ipsRaw {
		last := v[strings.LastIndex(v, "."):]
		if last == ".0" || last == ".255" {
			continue
		}
		ips = append(ips, v)
	}
	return
}

// IpsToCidr example 128.14.32.0, 128.14.47.255 -> 128.14.35.7/20
func IpsToCidr(firstStr string, lastStr string) (cidr string, err error) {
	first := strings.Split(firstStr, ".")
	last := strings.Split(lastStr, ".")
	var cidrSlice []string
	d := 0
	for i := 0; i < 4; i++ {
		f, _ := strconv.Atoi(first[i])
		l, _ := strconv.Atoi(last[i])
		if l < f {
			err = errors.New("empty")
			break
		}

		if l == f {
			cidrSlice = append(cidrSlice, fmt.Sprintf("%d", f))
			d += 8
			continue
		}

		m := ^(f ^ l) & 0xff
		fmt.Printf("f: %d m %d %b\n", f, m, m)

		z := 0xff
		n := 0
		for {
			if m == z {
				fmt.Printf("d  %d %d %b\n", d, m, m)
				break
			}
			m >>= 1
			z >>= 1
			n++
		}
		d += 8 - n

		//7

		w := ((^(f ^ l) & 0xff) >> (8 - n)) & 0xff
		cidrSlice = append(cidrSlice, fmt.Sprintf("%d", w))

		fmt.Printf("%d %d %d %b\n", d, f, l, m)
	}
	cidr = fmt.Sprintf("%s/%d", strings.Join(cidrSlice, "."), d)
	return
}
