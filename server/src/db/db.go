package db

import (
    "fmt"
    "context"
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
    "github.com/quangtrieu1312/masque-vpn/server/logger"
    "github.com/quangtrieu1312/masque-vpn/server/config"
)

type DB struct {
    conn *sql.DB
}

var dbInstance *DB = generateInstance()

func GetInstance() *DB {
    return dbInstance
}

func GetConnection() *sql.DB {
    return dbInstance.conn
}

func CloseConnection() {
    dbInstance.conn.Close()
}

func generateInstance() *DB {
    ctx := context.Background()
    config.Load(&ctx)
    info := ctx.Value("DB_INFO").(string)
    dbConn, err := sql.Open("sqlite3", info)
    if err != nil {
        logger.Fatal(fmt.Sprintf("cannot connect to DB: %v",err))
    }
    instance := &DB{dbConn}
    return instance
}

