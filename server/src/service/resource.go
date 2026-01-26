package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllResources(ctx context.Context) (*[]domain.Resource, error) {
    return repository.GetAllResources()
}
func GetClientResources(ctx context.Context, name string) (*[]domain.Resource, error) {
    return repository.GetClientResources(name)
}
func UpsertResources(ctx context.Context, resources *[]domain.Resource) (bool, error) {
    return repository.UpsertResources(resources)
}
func UpdateResourceName(ctx context.Context, oldName string, newName string) (bool, error) {
    return repository.UpdateResourceName(oldName, newName)
}
func DeleteResources(ctx context.Context, resourceNames []string) (bool, error) {
    return repository.DeleteResources(resourceNames)
}
