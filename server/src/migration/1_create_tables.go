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
    db.GetConnection().Exec(`
        CREATE TABLE IF NOT EXISTS migration (
            version integer NOT NULL,
            status integer NOT NULL DEFAULT 0,
            description text,
            PRIMARY KEY (version)
        )`)
    db.GetConnection().Exec(`
        INSERT INTO TABLE migration(version, status, description)
        VALUES(?, ?, ?)
        `, m.Version, Pending, m.Description)
    er := tx.Commit()
    if er != nil {
        tx.Rollback()
        logger.Fatal(fmt.Sprintf("cannot commit transaction: %v", er))
    }
    return 0
}

