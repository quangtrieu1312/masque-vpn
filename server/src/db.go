package main

import (
    "sync"
	"gorm.io/gorm"
    "gorm.io/driver/sqlite"
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
            dbConn, err:= gorm.Open(sqlite.Open(DB_PATH), &gorm.Config{})
            if err != nil {
                LogFatal("Cannot connect to DB")
            }
            dbInstance := &DB{dbConn}
            return dbInstance
        }
    }
    return dbInstance
}

