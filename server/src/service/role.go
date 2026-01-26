package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllRoles(ctx context.Context) (*[]domain.Role, error) {
    return repository.GetAllRoles()
}
func AssignResourcesToRole(ctx context.Context, resourceNames []string, roleName string) (bool, error) {
    return repository.AssignResourcesToRole(resourceNames, roleName)
}
func UnassignResourcesToRole(ctx context.Context, resourceNames []string, roleName string) (bool, error) {
    return repository.UnassignResourcesToRole(resourceNames, roleName)
}
func UpdateRoleName(ctx context.Context, oldName string, newName string) (bool, error) {
    return repository.UpdateRoleName(oldName, newName)
}
func UpsertRoles(ctx context.Context, roles *[]domain.Role) (bool, error) {
    return repository.UpsertRoles(roles)
}
func DeleteRoles(ctx context.Context, roleNames []string) (bool, error) {
    return repository.DeleteRoles(roleNames)
}
