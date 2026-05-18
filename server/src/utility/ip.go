package utility

import (
    "fmt"
	"net"
	"net/netip"
    "github.com/praserx/ipconv"
)

func IPv4ToInt(ip net.IP) uint32 {
    ret, _ := ipconv.IPv4ToInt(ip)
    return ret
}

func IntToIPv4(num uint32) net.IP {
    return ipconv.IntToIPv4(num)
}

func ParseIP(s string) (net.IP, int, error) {
    return ipconv.ParseIP(s)
}

func FirstIP(cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }
    netAddr := prefix.Addr()
    return netAddr.Next().String(), nil
}

func FirstUsableIP(cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }
    netAddr := prefix.Addr()
    if prefix.Bits() == 32 {
        return "", fmt.Errorf("Cannot handle /32")
    } else if prefix.Bits() == 31 {
        return netAddr.String(), nil
    }
    return netAddr.Next().String(), nil
}

func LastIP(cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }
    return LastIPAddr(prefix).String(), nil
}

func LastUsableIP(cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }
    broadcastAddr := LastIPAddr(prefix)
    if prefix.Bits() == 32 {
        return "", fmt.Errorf("Cannot handle /32")
    } else if prefix.Bits() == 31 {
        return broadcastAddr.String(), nil
    }
    return LastIPAddr(prefix).Prev().String(), nil

}

func LastIPAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	bytes := addr.AsSlice()

	hostBits := len(bytes)*8 - prefix.Bits()
	for i := len(bytes) - 1; i >= 0; i-- {
        setBits := 8
        if setBits > hostBits {
            setBits = hostBits
        }
		if setBits <= 0 {
			break
		}
		bytes[i] |= byte(0xff >> (8 - setBits))
		hostBits -= 8
	}

	if addr.Is4() {
		return netip.AddrFrom4(*(*[4]byte)(bytes[:4]))
	}
	return netip.AddrFrom16(*(*[16]byte)(bytes))
}

func PrefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
}
