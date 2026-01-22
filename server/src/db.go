package main

import (
    "fmt"
    "sync"
    "context"
	"gorm.io/gorm"
    "gorm.io/driver/postgres"
)

var dbLock = &sync.Mutex{}

type DB struct {
    conn *gorm.DB
}

var dbInstance *DB

func GetDBInstance(ctx context.Context) *DB {
    if dbInstance == nil {
        lock.Lock()
        defer lock.Unlock()
        if dbInstance == nil {
            host := ctx.Value("DB_HOST").(string)
            port := ctx.Value("DB_PORT").(string)
            name := ctx.Value("DB_NAME").(string)
            username := ctx.Value("DB_USERNAME").(string)
            password := ctx.Value("DB_PASSWORD").(string)
            dsn := fmt.Sprintf("host=%v port=%v user=%v password=%v dbname=%v sslmode=disable", host, port, username, password, name)
            dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
            if err != nil {
                LogFatal("Cannot connect to DB")
            }
            dbInstance := &DB{dbConn}
            return dbInstance
        }
    }
    return dbInstance
}

