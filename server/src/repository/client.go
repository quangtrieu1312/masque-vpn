package repository

import (
	"context"
    _ "github.com/lib/pq"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

func GetAllClients(ctx context.Context) ([]*Client, error) {
    db := GetDBInstance(ctx).conn
    clients, err := gorm.G[*Client](db).Find(ctx)
    return clients, err
}

func GetClientById(ctx context.Context, id string) (*Client, error) {
    db := GetDBInstance(ctx).conn
    client, err := gorm.G[*Client](db).Where("id = ?", id).First(ctx)
    return client, err
}

func AssignRolesToClient(ctx context.Context, roleNames []string, clientId string) (bool, error) {
    db := GetDBInstance(ctx).conn
    err := db.Transaction(func(tx *gorm.DB) error {
        roles, rerr := gorm.G[*Role](tx).Where("name in ?", roleNames).Find(ctx)
        if rerr != nil {
            return rerr
        }
        _, e := gorm.G[*Client](db).Where("id = ?", clientId).Update(ctx, "roles", roles)

        return e
    })
    if err != nil {
        return false, err
    }
    return true, nil
}

func CreateClients(ctx context.Context, clientNames []string) (bool, error) {
    db := GetDBInstance(ctx).conn
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

func DeleteClients(ctx context.Context, clientIds []string) (bool, error) {
    db := GetDBInstance(ctx).conn
    _, err := gorm.G[*Client](db).Where("id IN ?", clientIds).Delete(ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func DeleteRoles(ctx context.Context, roleNames []string) (bool, error) {
    db := GetDBInstance(ctx).conn
    _, err := gorm.G[*Role](db).Where("name IN ?", roleNames).Delete(ctx)
    if err != nil {
        return false, err
    }
    return true, nil
}

func AssignIPToClient(ctx context.Context, clientId string) (string, error) {
    db := GetDBInstance(ctx).conn
    assignedIP := ""
    err := db.Transaction(func(tx *gorm.DB) error {
        oldIp, oerr := gorm.G[*IP](db).Where("client_id = ?", clientId).First(ctx)
        if oerr == nil && len(oldIp.Value) > 0 {
            assignedIP = oldIp.Value
            return nil
        }
        dhcp, err := gorm.G[*DHCP](tx).First(ctx)
        if err != nil {
            return err
        }
        assignedIP = dhcp.NextAvailableIP
        _, e := gorm.G[*IP](db).Where("client_id = ?", clientId).Update(ctx, "value", assignedIP)
        if e != nil {
            return e
        }
        nextIP, e:= NextIP(assignedIP, dhcp.ClientCIDR)
        if e != nil {
            return e
        }

        _, er := gorm.G[*DHCP](db).Update(ctx, "value", nextIP)

        return er
    })
    return assignedIP, err
}
