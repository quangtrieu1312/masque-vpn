package main

import (
    "sync"
    "strings"
    "fmt"
    "net"
)

type IpStatus int

const (
    UNASSIGNED IpStatus = iota
    ASSIGNED
    RESERVED_FOR_ROUTER
)

var ipStatusName = map[IpStatus]string {
    UNASSIGNED: "UNASSIGNED",
    ASSIGNED: "ASSIGNED",
    RESERVED_FOR_ROUTER: "RESERVED_FOR_ROUTER",
}

func ConvertStringToIpStatus(statusName string) IpStatus {
    switch (strings.ToUpper( statusName)) {
    case "UNASSIGNED":
        return UNASSIGNED
    case "ASSIGNED":
        return ASSIGNED
    case "RESERVED_FOR_ROUTER":
        return RESERVED_FOR_ROUTER
    default:
        LogError(fmt.Sprintf("[ERROR]: Invalid ip status: %v. Defaulting to `ASSIGNED`", statusName))
        return ASSIGNED
    }
}

var mu = &sync.RWMutex{}

type IpManager struct {
    nextIp net.IP
    assignSubnet *net.IPNet
    clientIpMap map[string]string
    ipMap map[string]IpStatus
}

var ipManInstance *IpManager

func GetIpManagerInstance(ip net.IP, subnet *net.IPNet) *IpManager {
    if ipManInstance == nil {
        mu.Lock()
        defer mu.Unlock()
        if ipManInstance == nil {
            ipManInstance = &IpManager{ ip, subnet, make(map[string]string), make(map[string]IpStatus) }
            ipManInstance.nextIp = ip
        }
    }
    return ipManInstance
}

func increaseIp(ip net.IP, ipnet *net.IPNet) {
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

func GetAssignSubnet() *net.IPNet {
    mu.RLock()
    defer mu.RUnlock()
    return ipManInstance.assignSubnet
}

func GetAndIncrementNextIp() (net.IP, *net.IPNet, error) {
    mu.Lock()
    defer mu.Unlock()
    oldVal:= make(net.IP, len(ipManInstance.nextIp))
    copy(oldVal, ipManInstance.nextIp)
    newVal:= make(net.IP, len(ipManInstance.nextIp))
    copy(newVal, ipManInstance.nextIp)
    increaseIp(newVal, ipManInstance.assignSubnet)
    if (newVal.Equal(oldVal)) {
        return nil, nil, fmt.Errorf("Ran out of virtual IPs")
    }
    for (ipManInstance.ipMap[newVal.String()]!=UNASSIGNED) {
        increaseIp(newVal, ipManInstance.assignSubnet)
        if (newVal.Equal(oldVal)) {
            return nil, nil, fmt.Errorf("Ran out of virtual IPs")
        }
    }
    ipManInstance.nextIp = newVal
    return oldVal, ipManInstance.assignSubnet, nil
}

func GetClientIp(clientId string) (string, error) {
    mu.RLock()
    defer mu.RUnlock()
    if item, ok := ipManInstance.clientIpMap[clientId]; ! ok {
        return item, fmt.Errorf("Client id %v does not have an IP", clientId)
    } else {
        return item, nil
    }
}

func UpdateClientIp(clientId string, newIp string) error {
    mu.Lock()
    defer mu.Unlock()
    if _, ok := ipManInstance.clientIpMap[clientId]; ! ok {
        return fmt.Errorf("Client id %v may not exists", clientId)
    } else {
        ipManInstance.clientIpMap[clientId]=newIp
        return nil
    }
}

func InsertClientIp(clientId string, newIp string) error {
    mu.Lock()
    defer mu.Unlock()
    if ip, ok := ipManInstance.clientIpMap[clientId]; ok {
        return fmt.Errorf("Client id %v already has an IP %v", clientId, ip)
    } else {
        if ipStatus, ok := ipManInstance.ipMap[newIp]; ! ok {
            ipManInstance.clientIpMap[clientId] = newIp
            ipManInstance.ipMap[newIp] = ASSIGNED
            return nil
        } else if ipStatus == UNASSIGNED {
            ipManInstance.clientIpMap[clientId] = newIp
            ipManInstance.ipMap[newIp] = ASSIGNED
            return nil
        }
        return fmt.Errorf("IP %v is either already assigned or reserved")
    }
}

func UpsertClientIp(clientId string, newIp string) error {
    mu.Lock()
    defer mu.Unlock()
    if ipStatus, ok := ipManInstance.ipMap[newIp]; ! ok {
        ipManInstance.clientIpMap[clientId] = newIp
        ipManInstance.ipMap[newIp] = ASSIGNED
        return nil
    } else if ipStatus == UNASSIGNED {
        ipManInstance.clientIpMap[clientId] = newIp
        ipManInstance.ipMap[newIp] = ASSIGNED
        return nil
    }
    return fmt.Errorf("IP %v is either already assigned or reserved")
}


