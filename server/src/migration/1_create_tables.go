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
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS migration (
            version integer NOT NULL,
            status integer NOT NULL DEFAULT 0,
            description text,
            PRIMARY KEY (version)
        )`)
    tx.Exec(`
        INSERT INTO TABLE migration(version, status, description)
        VALUES($1, $2, $3)
        ON CONFLICT (version)
        DO NOTHING
        `, m.Version, Succeeded, m.Description)

    //Create table for domains
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS clients (
            name text NOT NULL,
            last_seen integer NOT NULL DEFAULT 0,
            ip text NOT NULL,
            PRIMARY KEY (name)
        )`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS resources (
            name text NOT NULL,
            value text NOT NULL,
            PRIMARY KEY (name)
        )`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS roles (
            name text NOT NULL,
            PRIMARY KEY (name)
        )`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS dhcp (
            first_ip bigint NOT NULL UNIQUE,
            last_ip bigint NOT NULL UNIQUE,
        )`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS clients_roles (
            client_name text NOT NULL,
            role_name text NOT NULL,
            CONSTRAINT fk_client FOREIGN KEY (client_name)
            REFERENCES clients(name) ON DELETE CASCADE,
            CONSTRAINT fk_role FOREIGN KEY (role_name)
            REFERENCES roles(name) ON DELETE CASCADE,
        )`)
    tx.Exec(`
        CREATE TABLE IF NOT EXISTS roles_resources (
            role_name text NOT NULL,
            resource_name text NOT NULL,
            CONSTRAINT fk_role FOREIGN KEY (role_name)
            REFERENCES roles(name) ON DELETE CASCADE,
            CONSTRAINT fk_resource FOREIGN KEY (resource_name)
            REFERENCES resources(name) ON DELETE CASCADE,
        )`)
    er := tx.Commit()
    if er != nil {
        logger.Debug(fmt.Sprintf("cannot commit transaction: %v", er))
        return 1
    }
    return 0
}

