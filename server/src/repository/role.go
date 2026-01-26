package repository

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
)

func GetAllRoles(ctx context.Context) ([]*Role, error) {
    db := GetDBInstance(ctx).conn
    roles, err := gorm.G[*Role](db).Find(ctx)
    return roles, err
}

func AssignResourcesToRole(ctx context.Context, resourceNames []string, roleName string) (bool, error) {
    db := GetDBInstance(ctx).conn
    err := db.Transaction(func(tx *gorm.DB) error {
        resources, rerr := gorm.G[*Role](tx).Where("name in ?", resourceNames).Find(ctx)
        if rerr != nil {
            return rerr
        }
        _, e := gorm.G[*Role](db).Where("name = ?", roleName).Update(ctx, "resources", resources)

        return e
    })
    if err != nil {
        return false, err
    }
    return true, nil
}

func CreateRoles(ctx context.Context, roles []*Role) (bool, error) {
    db := GetDBInstance(ctx).conn
    result := db.Create(roles)
    if result.Error != nil {
        return false, result.Error
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
