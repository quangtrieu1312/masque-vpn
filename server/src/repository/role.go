package repository

import (
	"fmt"

	_ "github.com/mattn/go-sqlite3"

	"github.com/quangtrieu1312/masque-vpn/server/db"
	"github.com/quangtrieu1312/masque-vpn/server/domain"
	"github.com/quangtrieu1312/masque-vpn/server/utility"
)

func GetAllRoles() (*[]domain.Role, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
	defer tx.Rollback()
    roles := []domain.Role{}
    rows, err := tx.Query("SELECT id, name FROM roles")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Role{}
	    err := rows.Scan(&r.ID, &r.Name)
	    if err != nil {
		    return nil, err
	    }
        roles = append(roles, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &roles, nil   
}

func GetRoleByID(roleID int64) (*domain.Role, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
	defer tx.Rollback()
    role := domain.Role{}
    err = tx.QueryRow("SELECT id, name FROM roles WHERE id = ?", roleID).Scan(&role.ID, &role.Name)
    if err != nil {
        return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &role, nil   
}

func AssignResourcesToRoles(resourceIDs []int64, roleIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
	defer tx.Rollback()
    stmt, err := tx.Prepare(`
        INSERT INTO roles_resources(role_id, resource_id)
        VALUES (?, ?)
        ON CONFLICT (role_id, resource_id)
        DO NOTHING
    `)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    for _, roleID := range(roleIDs) {
        for _, resourceID := range(resourceIDs) {
            _, err = stmt.Exec(roleID, resourceID)
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

func UnassignResourcesToRoles(resourceIDs []int64, roleIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
	defer tx.Rollback()
    stmt, err := tx.Prepare(fmt.Sprintf(`
        DELETE FROM roles_resources
        WHERE role_id IN (%v) and resource_id IN (%v)
    `, utility.Int64ArrayInCSVFormat(roleIDs), utility.Int64ArrayInCSVFormat(resourceIDs)))
    if err != nil {
	    return false, err
    }
    defer stmt.Close()
    _, err = stmt.Exec()
    if err != nil {
        return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func UpdateRoleName(roleID int64, newName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
	defer tx.Rollback()
    stmt, err := tx.Prepare(`UPDATE roles SET name = ? WHERE id = ?`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(newName, roleID)

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func UpsertRoles(roleNames []string) (*[]int64, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
	defer tx.Rollback()
    stmt, err := tx.Prepare(`
        INSERT INTO roles(name)
        VALUES(?)
        ON CONFLICT (name)
        DO NOTHING
        `)
    if err != nil {
	    return nil, err
    }
    defer stmt.Close()
	roleIDs := []int64{}
    for _, role := range(roleNames) {
		result, err := stmt.Exec(role)
        id, err := result.LastInsertId()
        if err != nil {
	        return nil, err
        }
		roleIDs = append(roleIDs, id)
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &roleIDs, nil
}

func DeleteRoles(roleIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
	defer tx.Rollback()
    stmt, err := tx.Prepare(fmt.Sprintf(`DELETE FROM roles WHERE id IN (%v)`, utility.Int64ArrayInCSVFormat(roleIDs)))
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec()

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil   
}

func GetClientRoles(clientID int64) (*[]domain.Role, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
	defer tx.Rollback()
    roles := []domain.Role{}

    rows, err := tx.Query(`
        SELECT r.id, r.name
		FROM clients_roles as cr
		JOIN roles as r
		ON cr.role_id = r.id
        WHERE cr.client_id = ?`, clientID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Role{}
	    err := rows.Scan(&r.ID, &r.Name)
	    if err != nil {
		    return nil, err
	    }
        roles = append(roles, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }

    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &roles, nil
}
