package migration

import (
)

type MigrationStatus int

const (
    Pending MigrationStatus = iota
    Executed
    Succeeded
    Failed
    Unknown
)

type Migration interface {
    Run() int
}

func GenerateMigrationList() []Migration {
    migrations := []Migration{}
    migrations = append(migrations, GetMigration1())
    migrations = append(migrations, GetMigration2())
    migrations = append(migrations, GetMigration3())
    migrations = append(migrations, GetMigration4())
    return migrations
}

func Invoke() {
    migrations := GenerateMigrationList()
    for i:=0; i<len(migrations); i++ {
        migrations[i].Run()
    }
}
