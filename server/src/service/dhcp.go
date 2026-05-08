package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllAvailableIPRanges(ctx context.Context) (*[]domain.DHCP, error) {
    return repository.GetAllAvailableIPRanges()
}
func ResetDHCP(ctx context.Context, firstIP int64, lastIP int64) (bool, error) {
    return repository.ResetDHCP(firstIP, lastIP)
}
