package repository

import (
//	"database/sql"
    "github.com/lib/pq"

    "github.com/quangtrieu1312/masque-vpn/server/domain"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

func GetAllResources() (*[]domain.Resource, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    resources := []domain.Resource{}
    rows, err := tx.Query("SELECT name, value FROM resources")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Resource{}
	    err := rows.Scan(&r.Name, &r.Value)
	    if err != nil {
		    return nil, err
	    }
        resources = append(resources, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    return &resources, err
}

func GetClientResources(name string) (*[]domain.Resource, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    resources := []domain.Resource{}

    rows, err := tx.Query(`
        SELECT r.name, r.value 
        FROM resources as r
        JOIN roles_resources as rr
        ON r.name = rr.resource_name
        JOIN clients_roles as cr
        ON cr.role_name = rr.role_name
        WHERE cr.client_name = $1`, name)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Resource{}
	    err := rows.Scan(&r.Name, &r.Value)
	    if err != nil {
		    return nil, err
	    }
        resources = append(resources, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    return &resources, nil
}

func UpsertResources(resources *[]domain.Resource) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO resources(name, value)
        VALUES($1, $2)
        ON CONFLICT (name)
        DO UPDATE SET value = $2
        )`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    for _, resource := range(*resources) {
        _, err = stmt.Exec(resource.Name, resource.Value)

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

func UpdateResourceName(oldName string, newName string) (bool, error) {
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

func DeleteResources(resourceNames []string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`DELETE FROM resources WHERE name = ANY($1)`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(pq.Array(resourceNames))

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

