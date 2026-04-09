package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

type ResourceRequest struct {
	Name string
	Value string
}

func GetAllResources(ctx context.Context) (*[]domain.Resource, error) {
    return repository.GetAllResources()
}
func GetResourceByID(ctx context.Context, resourceID int64) (*domain.Resource, error) {
    return repository.GetResourceByID(resourceID)
}
func GetClientResources(ctx context.Context, clientID int64) (*[]domain.Resource, error) {
    return repository.GetClientResources(clientID)
}
func UpsertResources(ctx context.Context, resources []ResourceRequest) (*[]int64, error) {
    return repository.UpsertResources(resources)
}
func UpdateResourceName(ctx context.Context, resourceID int64, newName string) (bool, error) {
    return repository.UpdateResourceName(resourceID, newName)
}
func DeleteResources(ctx context.Context, resourceIDs []int64) (bool, error) {
    return repository.DeleteResources(resourceIDs)
}
