package repository

import (
    "fmt"
	"database/sql"
    _ "github.com/mattn/go-sqlite3"

    "github.com/quangtrieu1312/masque-vpn/server/db"
	"github.com/quangtrieu1312/masque-vpn/server/domain"
	"github.com/quangtrieu1312/masque-vpn/server/utility"
)

func GetAllClients() (*[]domain.Client, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    clients := []domain.Client{}
    rows, err := tx.Query("SELECT id, name, ip, last_seen FROM clients")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        c := domain.Client{}
	    err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.LastSeen)
	    if err != nil {
		    return nil, err
	    }
        clients = append(clients, c)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &clients, nil
}

func GetClientByID(clientID int64) (*domain.Client, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    client := domain.Client{}
    err = tx.QueryRow("SELECT id, name, ip, last_seen FROM clients WHERE id = ?", clientID).Scan(&client.ID, &client.Name, &client.IP, &client.LastSeen)
    if err != nil {
        return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &client, nil
}

func UpsertClients(clientNames []string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO clients(name, ip)
        VALUES(?, ?)
        ON CONFLICT (name)
        DO NOTHING
        `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    for i := 0; i < len(clientNames); i++ {
        client := domain.Client{}
        client.Name = clientNames[i]

        dhcp := domain.DHCP{}
        err = tx.QueryRow("SELECT id, first_ip, last_ip FROM dhcp ORDER BY first_ip ASC").Scan(&dhcp.ID, &dhcp.FirstIP, &dhcp.LastIP)
        if err != nil {
	        return false, err
        }

        client.IP = utility.IntToIPv4(uint32(dhcp.FirstIP)).String()
        if dhcp.FirstIP == dhcp.LastIP {
            _, err = tx.Exec("DELETE FROM dhcp WHERE id = ?", dhcp.ID)
            if err != nil {
	            return false, err
            }
        } else {
            _, err = tx.Exec("UPDATE dhcp SET first_ip = ?, last_ip = ? WHERE id = ?", dhcp.FirstIP + 1, dhcp.LastIP, dhcp.ID)
            if err != nil {
	            return false, err
            }
        }

        _, err = stmt.Exec(client.Name, client.IP)

        if err != nil {
	        return false, err
        }
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func AssignIPToClient(clientID int64) (string, error) { 
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return "", err
    }
    var ip string
    err = tx.QueryRow("SELECT ip FROM clients WHERE id = ?", clientID).Scan(&ip)
    if err != nil {
	    return "", err
    }
    if ip != "" {
        return ip, nil
    }
    dhcp := domain.DHCP{}
    err = tx.QueryRow("SELECT ip, first_ip, last_ip FROM dhcp ORDER BY first_ip ASC").Scan(&dhcp.ID, &dhcp.FirstIP, &dhcp.LastIP)
    if err != nil {
	    return "", err
    }
    _, err = tx.Exec("UPDATE dhcp SET first_ip = ?, last_ip = ? WHERE id = ?", dhcp.FirstIP + 1, dhcp.LastIP, dhcp.ID)
    if err != nil {
	    return "", err
    }
    ip = utility.IntToIPv4(uint32(dhcp.FirstIP)).String()
    _, err = tx.Exec("UPDATE clients SET ip = ? WHERE id = ?", ip, clientID)
    if err != nil {
	    return "", err
    }
    err = tx.Commit()
    if err != nil {
        return "", err
    }
    return ip, nil
}

func DeleteClients(clientIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare("DELETE FROM client WHERE id = ?")
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    for i := 0; i < len(clientIDs); i++ {
        client := domain.Client{}
        err = tx.QueryRow("SELECT id, name, ip, last_seen FROM client WHERE id = ?", clientIDs[i]).Scan(&client.ID, &client.Name, &client.IP, &client.LastSeen)
        if err != nil {
	        return false, err
        }

        _, ipInt, err := utility.ParseIP(client.IP)
        if err != nil {
            return false, err
        }
        dhcp1 := domain.DHCP{}
        err1 := tx.QueryRow("SELECT first_ip, last_ip FROM dhcp WHERE last_ip = ?", ipInt-1).Scan(&dhcp1.FirstIP, &dhcp1.LastIP)

        dhcp2 := domain.DHCP{}
        err2 := tx.QueryRow("SELECT first_ip, last_ip FROM dhcp WHERE first_ip = ?", ipInt+1).Scan(&dhcp2.FirstIP, &dhcp2.LastIP)

        // Return IP to DHCP pool
        if err1 == sql.ErrNoRows && err2 == sql.ErrNoRows {
            // There is nothing to merge
            _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES(?, ?)", ipInt)
            if err != nil {
	            return false, err
            }
        } else if err1 == nil && err2 == sql.ErrNoRows {
            // Merge [dhcp1.FirstIP, ipInt-1] with [ipInt, ipInt]
            _, err = tx.Exec("UPDATE dhcp SET first_ip = ?, last_ip = ? WHERE first_ip = ? and last_ip = ?", dhcp1.FirstIP, dhcp1.LastIP + 1, dhcp1.FirstIP, dhcp1.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 == sql.ErrNoRows && err2 == nil {
            // Merge [ipInt, ipInt] with [ipInt+1, dhcp2.LastIP]
            _, err = tx.Exec("UPDATE dhcp SET first_ip = ?, last_ip = ? WHERE first_ip = ? and last_ip = ?", dhcp2.FirstIP-1, dhcp2.LastIP, dhcp2.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 == nil && err2 == nil {
            // Merge [dhcp1.FirstIP, ipInt-1] with [ipInt, ipInt] with [ipInt+1, dhcp2.LastIP]
            _, err = tx.Exec("DELETE FROM dhcp WHERE (first_ip = ? and last_ip = ?) or (first_ip = ? and last_ip = ?)", dhcp1.FirstIP, dhcp1.LastIP, dhcp2.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
            _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES(?, ?)", dhcp1.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 != nil {
            return false, err1
        } else {
            return false, err2
        }

        _, err = stmt.Exec(clientIDs[i])

        if err != nil {
	        return false, err
        }
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func UnassignRolesToClients(roleIDs []int64, clientIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(fmt.Sprintf(`
        DELETE FROM clients_roles
        WHERE client_id IN (%v) and role_id IN (%v)
    `, utility.Int64ArrayInCSVFormat(clientIDs), utility.Int64ArrayInCSVFormat(roleIDs)))
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    _, err = stmt.Exec()
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func AssignRolesToClients(roleIDs []int64, clientIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO clients_roles(client_id, role_id)
        VALUES (?, ?)
        ON CONFLICT (client_id, role_id)
        DO NOTHING
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    for _, clientID := range(clientIDs) {
        for _, roleID := range(roleIDs) {
            _, err = stmt.Exec(clientID, roleID)
            if err != nil {
                return false, err
            }
        }
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func UpdateClientName(clientID int64, newName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`UPDATE clients SET name = ? WHERE id = ?`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(newName, clientID)

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}
