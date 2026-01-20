package main

import (
    "fmt"
	"context"
	"gorm.io/gorm"
)

type Client struct {
    gorm.Model
    Name string
    LastSeen uint64
    Roles []*Role `gorm:"many2many:clients_roles"`
}

type IP struct {
    gorm.Model
    ClientID string
    Client Client
    Value string `gorm:"primaryKey"`
}

type Role struct {
    gorm.Model
    Name string `gorm:"primaryKey"`
    Clients []*Client `gorm:"many2many:clients_roles"`
    Resources []*Resource `gorm:"many2many:roles_resources"`
}

type Resource struct {
    gorm.Model
    Name string `gorm:"primaryKey"`
    Value string
    Clients []*Client `gorm:"many2many:clients_resources"`
    Roles []*Role `gorm:"many2many:roles_resources"`
}

type DHCP struct {
    ClientCIDR string
    NextAvailableIP string
}

func GetAllClients(ctx *context.Context, db *gorm.DB) ([]*Client, error) {
    clients, err := gorm.G[*Client](db).Find(*ctx)
    return clients, err
}

func GetClientById(ctx *context.Context, db *gorm.DB, id string) (*Client, error) {
    client, err := gorm.G[*Client](db).Where("id = ?", id).First(*ctx)
    return client, err
}

func GetClientResources(ctx *context.Context, db *gorm.DB, id string) ([]*Resource, error) {
    LogDebug("0")
    LogDebug(fmt.Sprintf("%v", ctx))
    LogDebug(fmt.Sprintf("%v", db))
    client, err := gorm.G[*Client](db).Where("id = ?", id).First(*ctx)
    if err != nil {
        return nil, err
    }
    LogDebug("1")
    roles := client.Roles
    LogDebug("2")
    ret := []*Resource{}
    for i := 0; i < len(roles); i++ {
        ret = append(ret, roles[i].Resources...)
    }
    LogDebug("3")
    return ret, nil
}

func GetAllRoles(ctx *context.Context, db *gorm.DB) ([]*Role, error) {
    roles, err := gorm.G[*Role](db).Find(*ctx)
    return roles, err
}

func GetAllResources(ctx *context.Context, db *gorm.DB) ([]*Resource, error) {
    resources, err := gorm.G[*Resource](db).Find(*ctx)
    return resources, err
}

func AssignRolesToClient(ctx *context.Context, db *gorm.DB, roleNames []string, clientId string) (bool, error) {
    err := db.Transaction(func(tx *gorm.DB) error {
        roles, rerr := gorm.G[*Role](tx).Where("name in ?", roleNames).Find(*ctx)
        if rerr != nil {
            return rerr
        }
        _, e := gorm.G[*Client](db).Where("id = ?", clientId).Update(*ctx, "roles", roles)

        return e
    })
    if err != nil {
        return false, err
    }
    return true, nil
}

func AssignResourcesToRole(ctx *context.Context, db *gorm.DB, resourceNames []string, roleName string) (bool, error) {
    err := db.Transaction(func(tx *gorm.DB) error {
        resources, rerr := gorm.G[*Role](tx).Where("name in ?", resourceNames).Find(*ctx)
        if rerr != nil {
            return rerr
        }
        _, e := gorm.G[*Role](db).Where("name = ?", roleName).Update(*ctx, "resources", resources)

        return e
    })
    if err != nil {
        return false, err
    }
    return true, nil
}

func CreateClients(ctx *context.Context, db *gorm.DB, clientNames []string) (bool, error) {
    clients := []*Client{}
    for i := 0; i < len(clientNames); i++ {
        roles := []*Role{}
        clients = append(clients, &Client{
            Name: clientNames[i],
            Roles: append(roles, &Role{Name: clientNames[i]}),
        })
    }
    result := db.Create(clients)
    if result.Error != nil {
        return false, result.Error
    }
    return true, nil
}

func CreateRoles(ctx *context.Context, db *gorm.DB, roles []*Role) (bool, error) {
    result := db.Create(roles)
    if result.Error != nil {
        return false, result.Error
    }
    return true, nil
}

func CreateResources(ctx *context.Context, db *gorm.DB, resources []*Resource) (bool, error) {
    result := db.Create(resources)
    if result.Error != nil {
        return false, result.Error
    }
    return true, nil
}

func DeleteClients(ctx *context.Context, db *gorm.DB, clientIds []string) (bool, error) {
    _, err := gorm.G[*Client](db).Where("id IN ?", clientIds).Delete(*ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func DeleteRoles(ctx *context.Context, db *gorm.DB, roleNames []string) (bool, error) {
    _, err := gorm.G[*Role](db).Where("name IN ?", roleNames).Delete(*ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func DeleteResources(ctx *context.Context, db *gorm.DB, resourceNames []string) (bool, error) {
    _, err := gorm.G[*Resource](db).Where("name IN ?", resourceNames).Delete(*ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func GetDHCP(ctx *context.Context, db *gorm.DB) (*DHCP, error) {
    conf, err := gorm.G[*DHCP](db).First(*ctx)
    return conf, err
}

func CreateDHCP(ctx *context.Context, db *gorm.DB, newClientCIDR string) (bool, error) {
    firstIP, err := FirstIP(newClientCIDR)
    if err != nil {
        return false, err
    }
    result := db.Create(&DHCP{ClientCIDR: newClientCIDR, NextAvailableIP: firstIP})
    if result.Error != nil {
        return false, result.Error
    }
    return true, nil
}

func AssignIPToClient(ctx *context.Context, db *gorm.DB, clientId string) (string, error) {
    assignedIP := ""
    err := db.Transaction(func(tx *gorm.DB) error {
        oldIp, oerr := gorm.G[*IP](db).Where("client_id = ?", clientId).First(*ctx)
        if oerr == nil && len(oldIp.Value) > 0 {
            assignedIP = oldIp.Value
            return nil
        }
        dhcp, err := gorm.G[*DHCP](tx).First(*ctx)
        if err != nil {
            return err
        }
        assignedIP = dhcp.NextAvailableIP
        _, e := gorm.G[*IP](db).Where("client_id = ?", clientId).Update(*ctx, "value", assignedIP)
        if e != nil {
            return e
        }
        nextIP, e:= NextIP(assignedIP, dhcp.ClientCIDR)
        if e != nil {
            return e
        }

        _, er := gorm.G[*DHCP](db).Update(*ctx, "value", nextIP)

        return er
    })
    return assignedIP, err
}
