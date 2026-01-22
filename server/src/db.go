package main

import (
    "sync"
	"gorm.io/gorm"
    "gorm.io/driver/postgres"
)

var dbLock = &sync.Mutex{}

type DB struct {
    conn *gorm.DB
}

var dbInstance *DB

func GetDBInstance() *DB {
    if dbInstance == nil {
        lock.Lock()
        defer lock.Unlock()
        if dbInstance == nil {
            dsn := "host=postgres user=masqued password=maqued dbname=masqued port=5432 sslmode=disable"
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

