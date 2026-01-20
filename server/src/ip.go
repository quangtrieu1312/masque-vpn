package main

import (
    "fmt"
	"net"
	"net/netip"
)

func FirstIP(cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }
    netAddr := prefix.Addr()
    if !prefix.Contains(netAddr.Next()) {
        return "", fmt.Errorf("Cannot handle /32")
    }
    return netAddr.Next().String(), nil
}

func NextIP(ip string, cidr string) (string, error) {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return "", err
    }

    nextAddr, er := netip.ParseAddr(ip)
    if er != nil {
        return "", err
    }

    if !prefix.Contains(nextAddr.Next()) {
        return "", fmt.Errorf("Out of IP")
    }
    return nextAddr.Next().String(), nil

}

func IncreaseIp(ip net.IP, ipnet *net.IPNet) {
    oldIp:= make(net.IP, len(ip))
    copy(oldIp, ip)
	for j := len(ip) - 1; j >= 0; j-- {
		(ip)[j]++
		if (ip)[j] > 0 {
			break
		}
	}
    if (!ipnet.Contains(ip)) {
        ip=oldIp.Mask(ipnet.Mask)
    }
}

func LastIP(prefix netip.Prefix) netip.Addr {
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
