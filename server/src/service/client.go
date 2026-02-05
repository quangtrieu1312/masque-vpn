package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllClients(ctx context.Context) (*[]domain.Client, error) {
    return repository.GetAllClients()
}
func GetClientByID(ctx context.Context, id int64) (*domain.Client, error) {
    return repository.GetClientByID(id)
}
func UpsertClients(ctx context.Context, clientNames []string) (*[]int64, error) {
    return repository.UpsertClients(clientNames)
}
func AssignIPToClient(ctx context.Context, clientID int64) (string, error) { 
    return repository.AssignIPToClient(clientID)
}
func DeleteClients(ctx context.Context, clientIDs []int64) (bool, error) {
    return repository.DeleteClients(clientIDs)
}
func UnassignRolesToClients(ctx context.Context, roleIDs []int64, clientIDs []int64) (bool, error) {
    return repository.UnassignRolesToClients(roleIDs, clientIDs)
}
func AssignRolesToClients(ctx context.Context, roleIDs []int64, clientIDs []int64) (bool, error) {
    return repository.AssignRolesToClients(roleIDs, clientIDs)
}
func UpdateClientName(ctx context.Context, clientID int64, newName string) (bool, error) {
    return repository.UpdateClientName(clientID, newName)
}
