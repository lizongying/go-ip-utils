package iputils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntToIp4(t *testing.T) {
	res := IntToIp4(2148409344)
	t.Log(res)
	assert.Equal(t, res, "128.14.32.0")
}

func TestIp4ToInt(t *testing.T) {
	res := Ip4ToInt("128.14.32.0")
	t.Log(res)
	assert.Equal(t, res, 2148409344)
}

func TestBytesToIp4(t *testing.T) {
	res := BytesToIp4([]byte{128, 14, 32, 0})
	t.Log(res)
	assert.Equal(t, res, "128.14.32.0")
}

func TestBytesToIp6(t *testing.T) {
	res := BytesToIp6([]byte{254, 128, 0, 0, 9, 130, 42, 92, 0, 0, 0, 0, 0, 0, 255, 255})
	t.Log(res)
	assert.Equal(t, res, "fe80:0:982:2a5c:0:0:0:ffff")
}

func TestIp4ToBytes(t *testing.T) {
	res := Ip4ToBytes("128.14.32.0")
	t.Log(res)
	assert.Equal(t, res, []byte{128, 14, 32, 0})
}

func TestIp6ToBytes(t *testing.T) {
	res := Ip6ToBytes("fe80:0:982:2a5c:0:0:0:ffff")
	t.Log(res)
	assert.Equal(t, res, []byte{254, 128, 0, 0, 9, 130, 42, 92, 0, 0, 0, 0, 0, 0, 255, 255})
}

func TestIntToBytes(t *testing.T) {
	res := IntToBytes(2148409344)
	t.Log(res)
	assert.Equal(t, res, []byte{128, 14, 32, 0})
}

func TestBytesToInt(t *testing.T) {
	res := BytesToInt([]byte{128, 14, 32, 0})
	t.Log(res)
	assert.Equal(t, res, 2148409344)
}

func TestCidr4ToIps(t *testing.T) {
	res, _ := Cidr4ToIps("128.14.35.7/32")
	t.Log(res)
	assert.Equal(t, res, []string{"128.14.35.7"})
}

func TestCidr4ToIps2(t *testing.T) {
	res, _ := Cidr4ToIps("128.14.35.1/23")
	t.Log(res)
	assert.Equal(t, len(res), 512)
}

func TestCidr4ToIpsErr(t *testing.T) {
	res, _ := Cidr4ToIps("128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsErr2(t *testing.T) {
	res, _ := Cidr4ToIps("1128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsErr3(t *testing.T) {
	res, _ := Cidr4ToIps("128.14.35.337/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsClean(t *testing.T) {
	res, _ := Cidr4ToIpsClean("128.14.35.255/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsClean1(t *testing.T) {
	res, _ := Cidr4ToIpsClean("128.14.35.25/32")
	t.Log(res)
	assert.Equal(t, res, []string{"128.14.35.25"})
}

func TestCidr4ToIpsClean2(t *testing.T) {
	res, _ := Cidr4ToIpsClean("128.14.35.1/23")
	t.Log(res)
	assert.Equal(t, len(res), 508)
}

func TestCidr4ToIpsCleanErr(t *testing.T) {
	res, _ := Cidr4ToIpsClean("128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsCleanErr2(t *testing.T) {
	res, _ := Cidr4ToIpsClean("1128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidr4ToIpsCleanErr3(t *testing.T) {
	res, _ := Cidr4ToIpsClean("128.14.35.337/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestIpsToCidr(t *testing.T) {
	res, _ := IpsToCidr("128.14.35.7", "128.14.35.8")
	t.Log(res)
	//assert.Equal(t, res, []string{"128.14.35.7"})
}
