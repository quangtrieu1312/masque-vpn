package service

import (
	"context"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/repository"
)

func GetAllAvailableIPRanges(ctx context.Context) (*[]domain.DHCP, error) {
    return repository.GetAllAvailableIPRanges()
}
func ResetDHCP(ctx context.Context, dhcp *domain.DHCP) (bool, error) {
    return repository.ResetDHCP(dhcp)
}
