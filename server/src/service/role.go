package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllRoles(ctx context.Context) (*[]domain.Role, error) {
    return repository.GetAllRoles()
}
func GetRoleByID(ctx context.Context, id int64) (*domain.Role, error) {
    return repository.GetRoleByID(id)
}
func AssignResourcesToRoles(ctx context.Context, resourceIDs []int64, roleIDs []int64) (bool, error) {
    return repository.AssignResourcesToRoles(resourceIDs, roleIDs)
}
func UnassignResourcesToRoles(ctx context.Context, resourceIDs []int64, roleIDs []int64) (bool, error) {
    return repository.UnassignResourcesToRoles(resourceIDs, roleIDs)
}
func UpdateRoleName(ctx context.Context, roleID int64, newName string) (bool, error) {
    return repository.UpdateRoleName(roleID, newName)
}
func UpsertRoles(ctx context.Context, roleNames []string) (bool, error) {
    return repository.UpsertRoles(roleNames)
}
func DeleteRoles(ctx context.Context, roleIDs []int64) (bool, error) {
    return repository.DeleteRoles(roleIDs)
}
