package iputils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIntToIp(t *testing.T) {
	res := IntToIp(2148409344)
	t.Log(res)
	assert.Equal(t, res, "128.14.32.0")
}

func TestIpToInt(t *testing.T) {
	res := IpToInt("128.14.32.0")
	t.Log(res)
	assert.Equal(t, res, 2148409344)
}

func TestBytesToIp(t *testing.T) {
	var bs []byte
	bs = append(bs, 128, 14, 32, 0)
	res := BytesToIp(bs)
	t.Log(res)
	assert.Equal(t, res, "128.14.32.0")
}

func TestIpToBytes(t *testing.T) {
	res := IpToBytes("128.14.32.0")
	t.Log(res)
	assert.Equal(t, res, []byte{128, 14, 32, 0})
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

func TestCidrToIps(t *testing.T) {
	res, _ := CidrToIps("128.14.35.7/32")
	t.Log(res)
	assert.Equal(t, res, []string{"128.14.35.7"})
}

func TestCidrToIps2(t *testing.T) {
	res, _ := CidrToIps("128.14.35.1/23")
	t.Log(res)
	assert.Equal(t, len(res), 512)
}

func TestCidrToIpsErr(t *testing.T) {
	res, _ := CidrToIps("128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsErr2(t *testing.T) {
	res, _ := CidrToIps("1128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsErr3(t *testing.T) {
	res, _ := CidrToIps("128.14.35.337/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsClean(t *testing.T) {
	res, _ := CidrToIpsClean("128.14.35.255/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsClean1(t *testing.T) {
	res, _ := CidrToIpsClean("128.14.35.25/32")
	t.Log(res)
	assert.Equal(t, res, []string{"128.14.35.25"})
}

func TestCidrToIpsClean2(t *testing.T) {
	res, _ := CidrToIpsClean("128.14.35.1/23")
	t.Log(res)
	assert.Equal(t, len(res), 508)
}

func TestCidrToIpsCleanErr(t *testing.T) {
	res, _ := CidrToIpsClean("128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsCleanErr2(t *testing.T) {
	res, _ := CidrToIpsClean("1128.14.35.7/322")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}

func TestCidrToIpsCleanErr3(t *testing.T) {
	res, _ := CidrToIpsClean("128.14.35.337/32")
	t.Log(res)
	assert.Equal(t, res, []string(nil))
}
