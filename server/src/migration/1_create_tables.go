package migration

import (
    "fmt"
    "github.com/quangtrieu1312/masque-vpn/server/logger"
    "github.com/quangtrieu1312/masque-vpn/server/db"
)

type Migration1 struct {
    Version int
    Status MigrationStatus
    Description string
}

func GetMigration1() Migration1 {
    m := Migration1{}
    m.Version = 1
    m.Status = Unknown
    m.Description = "Create tables"
    return m
}

func (m Migration1) Run() int {
    logger.Info(fmt.Sprintf("DB migration %v: %v", m.Version, m.Description))
    tx, err := db.GetConnection().Begin()
    if err != nil {
        logger.Fatal(fmt.Sprintf("cannot start DB transaction: %v", err))
    }
    //Create table for migration
    tx.Exec(`CREATE TABLE IF NOT EXISTS migration (
            id integer NOT NULL PRIMARY KEY,
            version integer NOT NULL,
            status integer NOT NULL DEFAULT 0,
            description text)`)
    tx.Exec(`
        INSERT INTO TABLE migration(version, status, description)
        VALUES(?, ?, ?)
        ON CONFLICT (version)
        DO NOTHING
        `, m.Version, Succeeded, m.Description)

    //Create table for domains
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id integer PRIMARY KEY,
            name text NOT NULL UNIQUE,
            last_seen integer NOT NULL DEFAULT 0,
            ip text)`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS resources (
            id integer PRIMARY KEY,
            name text NOT NULL UNIQUE,
            value text NOT NULL)`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS roles (
            id integer PRIMARY KEY,
            name text NOT NULL UNIQUE)`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS dhcp (
            id integer PRIMARY KEY,
            first_ip bigint NOT NULL UNIQUE,
            last_ip bigint NOT NULL UNIQUE)`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS clients_roles (
            id integer PRIMARY KEY,
            client_id integer NOT NULL,
            role_id integer NOT NULL,
            CONSTRAINT fk_client FOREIGN KEY (client_id)
            REFERENCES clients(id) ON DELETE CASCADE,
            CONSTRAINT fk_role FOREIGN KEY (role_id)
            REFERENCES roles(id) ON DELETE CASCADE)`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS roles_resources (
            id integer PRIMARY KEY,
            role_id integer NOT NULL,
            resource_id integer NOT NULL,
            CONSTRAINT fk_role FOREIGN KEY (role_id)
            REFERENCES roles(id) ON DELETE CASCADE,
            CONSTRAINT fk_resource FOREIGN KEY (resource_id)
            REFERENCES resources(id) ON DELETE CASCADE)`)
    er := tx.Commit()
    if er != nil {
        logger.Debug(fmt.Sprintf("cannot commit transaction: %v", er))
        return 1
    }
    return 0
}

