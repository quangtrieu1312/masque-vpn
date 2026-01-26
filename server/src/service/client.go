package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllClients(ctx context.Context) (*[]domain.Client, error) {
    return repository.GetAllClients()
}
func GetClientByName(ctx context.Context, name string) (*domain.Client, error) {
    return repository.GetClientByName(name)
}
func UpsertClients(ctx context.Context, clientNames []string) (bool, error) {
    return repository.UpsertClients(clientNames)
}
func AssignIPToClient(ctx context.Context, clientName string) (string, error) { 
    return repository.AssignIPToClient(clientName)
}
func DeleteClients(ctx context.Context, clientNames []string) (bool, error) {
    return repository.DeleteClients(clientNames)
}
func UnassignRolesToClient(ctx context.Context, roleNames []string, clientName string) (bool, error) {
    return repository.UnassignRolesToClient(roleNames, clientName)
}
func AssignRolesToClient(ctx context.Context, roleNames []string, clientName string) (bool, error) {
    return repository.AssignRolesToClient(roleNames, clientName)
}
func UpdateClientName(ctx context.Context, oldName string, newName string) (bool, error) {
    return repository.UpdateClientName(oldName, newName)
}
