package repository

import (
	//"database/sql"
	"github.com/lib/pq"

    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

func GetAllRoles() (*[]domain.Role, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    roles := []domain.Role{}
    rows, err := tx.Query("SELECT name FROM roles")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Role{}
	    err := rows.Scan(&r.Name)
	    if err != nil {
		    return nil, err
	    }
        roles = append(roles, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    return &roles, nil   
}

func AssignResourcesToRole(resourceNames []string, roleName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO roles_resources(role_name, resource_name)
        VALUES ($1, $2)
        ON CONFLICT (role_name, resource_name)
        DO NOTHING
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    for _, resourceName := range(resourceNames) {
        _, err = stmt.Exec(roleName, resourceName)
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

func UnassignResourcesToRole(resourceNames []string, roleName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        DELETE FROM roles_resources
        WHERE role_name = $1 and resource_name = ANY($2)
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    _, err = stmt.Exec(roleName, pq.Array(resourceNames))
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func UpdateRoleName(oldName string, newName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`UPDATE roles SET name = $1 WHERE name = $2`)
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

func UpsertRoles(roles *[]domain.Role) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO roles(name)
        VALUES($1)
        ON CONFLICT (name)
        DO NOTHING
        )`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    for _, role := range(*roles) {
        _, err = stmt.Exec(role.Name)

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

func DeleteRoles(roleNames []string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`DELETE FROM roles WHERE name = ANY($1)`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(pq.Array(roleNames))

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil   
}
