package repository

import (
	"database/sql"
	"github.com/lib/pq"

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
    rows, err := tx.Query("SELECT name, ip, last_seen FROM clients")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        c := domain.Client{}
	    err := rows.Scan(&c.Name, &c.IP, &c.LastSeen)
	    if err != nil {
		    return nil, err
	    }
        clients = append(clients, c)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    return &clients, nil
}

func GetClientByName(name string) (*domain.Client, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    client := domain.Client{}
    err = tx.QueryRow("SELECT name, ip, last_seen FROM clients WHERE name = $1", name).Scan(&client.Name, &client.IP, &client.LastSeen)
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
        VALUES($1, $2)
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
        err = tx.QueryRow("SELECT first_ip, last_ip FROM dhcp ORDER BY first_ip ASC").Scan(&dhcp.FirstIP, &dhcp.LastIP)
        if err != nil {
	        return false, err
        }

        client.IP = utility.IntToIPv4(uint32(dhcp.FirstIP)).String()
        if dhcp.FirstIP == dhcp.LastIP {
            _, err = tx.Exec("DELETE FROM dhcp WHERE first_ip = $1 and last_ip = $2", dhcp.FirstIP, dhcp.LastIP)
            if err != nil {
	            return false, err
            }
        } else {
            _, err = tx.Exec("UPDATE dhcp SET first_ip = $1, last_ip = $2 WHERE first_ip = $3 and last_ip = $4", dhcp.FirstIP + 1, dhcp.LastIP, dhcp.FirstIP, dhcp.LastIP)
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

func AssignIPToClient(clientName string) (string, error) { 
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return "", err
    }
    var ip string
    err = tx.QueryRow("SELECT ip FROM clients WHERE name = $1", clientName).Scan(&ip)
    if err != nil {
	    return "", err
    }
    if ip != "" {
        return ip, nil
    }
    dhcp := domain.DHCP{}
    err = tx.QueryRow("SELECT first_ip, last_ip FROM dhcp ORDER BY first_ip ASC").Scan(&dhcp.FirstIP, &dhcp.LastIP)
    if err != nil {
	    return "", err
    }
    _, err = tx.Exec("UPDATE dhcp SET first_ip = $1, last_ip = $2 WHERE first_ip = $3 and last_ip = $4", dhcp.FirstIP + 1, dhcp.LastIP, dhcp.FirstIP, dhcp.LastIP)
    if err != nil {
	    return "", err
    }
    ip = utility.IntToIPv4(uint32(dhcp.FirstIP)).String()
    _, err = tx.Exec("UPDATE clients SET ip = $1 WHERE name = $2", ip, clientName)
    if err != nil {
	    return "", err
    }
    return ip, nil
}

func DeleteClients(clientNames []string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare("DELETE FROM client WHERE name = $1")
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    for i := 0; i < len(clientNames); i++ {
        client := domain.Client{}
        err = tx.QueryRow("SELECT name, ip, last_seen FROM client WHERE name = $1", clientNames[i]).Scan(&client.Name, &client.IP, &client.LastSeen)
        if err != nil {
	        return false, err
        }

        _, ipInt, err := utility.ParseIP(client.IP)
        if err != nil {
            return false, err
        }
        dhcp1 := domain.DHCP{}
        err1 := tx.QueryRow("SELECT first_ip, last_ip FROM dhcp WHERE last_ip = $1", ipInt-1).Scan(&dhcp1.FirstIP, &dhcp1.LastIP)

        dhcp2 := domain.DHCP{}
        err2 := tx.QueryRow("SELECT first_ip, last_ip FROM dhcp WHERE first_ip = $1", ipInt+1).Scan(&dhcp2.FirstIP, &dhcp2.LastIP)

        // Return IP to DHCP pool
        if err1 == sql.ErrNoRows && err2 == sql.ErrNoRows {
            // There is nothing to merge
            _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES($1, $1)", ipInt)
            if err != nil {
	            return false, err
            }
        } else if err1 == nil && err2 == sql.ErrNoRows {
            // Merge [dhcp1.FirstIP, ipInt-1] with [ipInt, ipInt]
            _, err = tx.Exec("UPDATE dhcp SET first_ip = $1, last_ip = $2 WHERE first_ip = $3 and last_ip = $4", dhcp1.FirstIP, dhcp1.LastIP + 1, dhcp1.FirstIP, dhcp1.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 == sql.ErrNoRows && err2 == nil {
            // Merge [ipInt, ipInt] with [ipInt+1, dhcp2.LastIP]
            _, err = tx.Exec("UPDATE dhcp SET first_ip = $1, last_ip = $2 WHERE first_ip = $3 and last_ip = $4", dhcp2.FirstIP-1, dhcp2.LastIP, dhcp2.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 == nil && err2 == nil {
            // Merge [dhcp1.FirstIP, ipInt-1] with [ipInt, ipInt] with [ipInt+1, dhcp2.LastIP]
            _, err = tx.Exec("DELETE FROM dhcp WHERE (first_ip = $1 and last_ip = $2) or (first_ip = $3 and last_ip = $4)", dhcp1.FirstIP, dhcp1.LastIP, dhcp2.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
            _, err = tx.Exec("INSERT INTO dhcp(first_ip, last_ip) VALUES($1, $2)", dhcp1.FirstIP, dhcp2.LastIP)
            if err != nil {
	            return false, err
            }
        } else if err1 != nil {
            return false, err1
        } else {
            return false, err2
        }

        _, err = stmt.Exec(clientNames[i])

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

func UnassignRolesToClient(roleNames []string, clientName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        DELETE FROM clients_roles
        WHERE client_name = $1 and role_name = ANY($2)
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    _, err = stmt.Exec(clientName, pq.Array(roleNames))
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func AssignRolesToClient(roleNames []string, clientName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO clients_roles(client_name, role_name)
        VALUES ($1, $2)
        ON CONFLICT (client_name, role_name)
        DO NOTHING
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    for _, roleName := range(roleNames) {
        _, err = stmt.Exec(clientName, roleName)
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

func UpdateClientName(oldName string, newName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`UPDATE resources SET name = $1 WHERE name = $2`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(newName, oldName)

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}
