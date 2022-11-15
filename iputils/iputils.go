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

// IntToIp example 2148409344 -> 128.14.32.0
func IntToIp(i int) (s string) {
	ips := []string{fmt.Sprintf("%d", i&0xff)}
	for k := 0; k < 3; k++ {
		i >>= 8
		ips = append([]string{fmt.Sprintf("%d", i&0xff)}, ips...)
	}
	s = strings.Join(ips, ".")
	return
}

// IpToInt example 128.14.32.0 -> 2148409344
func IpToInt(s string) (i int) {
	for k, a := range strings.Split(s, ".") {
		ai, _ := strconv.Atoi(a)
		i += ai << ((3 - k) * 8)
	}
	return
}

// BytesToIp example [128 14 32 0] -> 128.14.32.0
func BytesToIp(bs []byte) (s string) {
	var ips []string
	for _, i := range bs {
		ips = append(ips, fmt.Sprintf("%d", i))
	}
	s = strings.Join(ips, ".")
	return
}

// IpToBytes example 128.14.32.0 -> [128 14 32 0]
func IpToBytes(s string) (bs []byte) {
	for _, a := range strings.Split(s, ".") {
		ai, _ := strconv.Atoi(a)
		bs = append(bs, byte(ai))
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

// CidrToIps example 128.14.35.7/20 -> [128.14.32.0 ~ 128.14.47.255]
func CidrToIps(s string) (ips []string, err error) {
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
					ip := fmt.Sprintf("%d.%d.%d.%d", v0, v1, v2, v3)
					ips = append(ips, ip)
				}
			}
		}
	}
	return
}

// CidrToIpsClean example 128.14.35.7/20 -> [128.14.32.1 ~ 128.14.47.254]
func CidrToIpsClean(s string) (ips []string, err error) {
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
					if v3 == 0 || v3 == 0xff {
						continue
					}
					ip := fmt.Sprintf("%d.%d.%d.%d", v0, v1, v2, v3)
					ips = append(ips, ip)
				}
			}
		}
	}
	return
}
