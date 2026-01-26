package db

import (
    "fmt"
    "context"
    "database/sql"
    _ "github.com/lib/pq"
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
    host := ctx.Value("DB_HOST").(string)
    port := ctx.Value("DB_PORT").(string)
    name := ctx.Value("DB_NAME").(string)
    username := ctx.Value("DB_USERNAME").(string)
    password := ctx.Value("DB_PASSWORD").(string)
    info := fmt.Sprintf("host=%v port=%v user=%v password=%v dbname=%v sslmode=disable", host, port, username, password, name)
    dbConn, err := sql.Open("postgres", info)
    if err != nil {
        logger.Fatal(fmt.Sprintf("cannot connect to DB: %v",err))
    }
    instance := &DB{dbConn}
    return instance
}

