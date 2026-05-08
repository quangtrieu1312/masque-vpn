package repository

import (
//	"database/sql"
//	"github.com/lib/pq"

    _ "github.com/mattn/go-sqlite3"
    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

func GetAllAvailableIPRanges() (*[]domain.DHCP, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
	defer tx.Rollback()
    ipRanges := []domain.DHCP{}
    rows, err := tx.Query("SELECT id, first_ip, last_ip FROM dhcp")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        ipRange := domain.DHCP{}
	    err := rows.Scan(&ipRange.ID, &ipRange.FirstIP, &ipRange.LastIP)
	    if err != nil {
		    return nil, err
	    }
        ipRanges = append(ipRanges, ipRange)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &ipRanges, nil
}

func ResetDHCP(firstIP int64, lastIP int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
	defer tx.Rollback()
    _, err = tx.Exec("DELETE FROM dhcp")
    if err != nil {
        return false, err
    }
    _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES(?, ?)", firstIP, lastIP)
    if err != nil {
        return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}
