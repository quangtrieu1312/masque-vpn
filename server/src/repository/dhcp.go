package repository

import (
//	"database/sql"
//	"github.com/lib/pq"

    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

func GetAllAvailableIPRanges() (*[]domain.DHCP, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    ipRanges := []domain.DHCP{}
    rows, err := tx.Query("SELECT first_ip, last_ip FROM dhcp")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        ipRange := domain.DHCP{}
	    err := rows.Scan(&ipRange.FirstIP, &ipRange.LastIP)
	    if err != nil {
		    return nil, err
	    }
        ipRanges = append(ipRanges, ipRange)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    return &ipRanges, nil
}

func ResetDHCP(dhcp *domain.DHCP) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    _, err = tx.Exec("DELETE * FROM dhcp")
    if err != nil {
        return false, err
    }
    _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES($1, $2)", dhcp.FirstIP, dhcp.LastIP)
    if err != nil {
        return false, err
    }
    emptyString := ""
    _, err = tx.Exec("UPDATE clients SET ip = $1", emptyString)
    if err != nil {
        return false, err
    }
    return true, nil
}
