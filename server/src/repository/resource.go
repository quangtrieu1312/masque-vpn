package repository

import (
	"fmt"
	_ "github.com/mattn/go-sqlite3"

	"github.com/quangtrieu1312/masque-vpn/server/db"
	"github.com/quangtrieu1312/masque-vpn/server/domain"
	"github.com/quangtrieu1312/masque-vpn/server/utility"
	"github.com/quangtrieu1312/masque-vpn/server/request"
)


func GetAllResources() (*[]domain.Resource, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    resources := []domain.Resource{}
    rows, err := tx.Query("SELECT id, name, value FROM resources")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Resource{}
	    err := rows.Scan(&r.ID, &r.Name, &r.Value)
	    if err != nil {
		    return nil, err
	    }
        resources = append(resources, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &resources, err
}

func GetResourceByID(resourceID int64) (*domain.Resource, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    resource := domain.Resource{}
    err = tx.QueryRow("SELECT id, name, value FROM roles WHERE id = ?", resourceID).Scan(&resource.ID, &resource.Name, resource.Value)
    if err != nil {
        return nil, err
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &resource, nil   
}

func GetClientResources(clientID int64) (*[]domain.Resource, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    resources := []domain.Resource{}

    rows, err := tx.Query(`
        SELECT r.id, r.name, r.value 
        FROM resources as r
        JOIN roles_resources as rr
        ON r.id = rr.resource_id
        JOIN clients_roles as cr
        ON cr.role_id = rr.role_id
        WHERE cr.client_id = ?`, clientID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        r := domain.Resource{}
	    err := rows.Scan(&r.ID, &r.Name, &r.Value)
	    if err != nil {
		    return nil, err
	    }
        resources = append(resources, r)
    }
    err = rows.Err()
    if err != nil {
	    return nil, err
    }

    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &resources, nil
}

func UpsertResources(resources []request.ResourceRequest) (*[]int64, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return nil, err
    }
    stmt, err := tx.Prepare(`
        INSERT INTO resources(name, value)
        VALUES(?, ?)
        ON CONFLICT (name)
        DO UPDATE SET value = ?
        `)
    if err != nil {
	    return nil, err
    }
    defer stmt.Close()

    resourceIDs := []int64{}
    for _, resource := range(resources) {
		result, err := stmt.Exec(resource.Name, resource.Value)
        id, err := result.LastInsertId()

        if err != nil {
	        return nil, err
        }
        resourceIDs = append(resourceIDs, id) 
    }
    err = tx.Commit()
    if err != nil {
        return nil, err
    }
    return &resourceIDs, nil
}

func UpdateResourceName(resourceID int64, newName string) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(`UPDATE resources SET name = ? WHERE id = ?`)
    if err != nil {
	    return false, err
    }
    defer stmt.Close()

    _, err = stmt.Exec(newName, resourceID)

    if err != nil {
	    return false, err
    }
    err = tx.Commit()
    if err != nil {
        return false, err
    }
    return true, nil
}

func DeleteResources(resourceIDs []int64) (bool, error) {
    tx, err := db.GetConnection().Begin()
    if err != nil {
        return false, err
    }
    stmt, err := tx.Prepare(fmt.Sprintf(`DELETE FROM resources WHERE id IN (%v)`, utility.Int64ArrayInCSVFormat(resourceIDs)))
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

