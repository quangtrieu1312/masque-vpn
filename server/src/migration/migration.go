package migration

import (
    "context"
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
    Run(ctx context.Context) int
}

func GenerateMigrationList() []Migration {
    migrations := []Migration{}
    migrations = append(migrations, GetMigration1())
    return migrations
}

func Invoke(ctx context.Context) {
    migrations := GenerateMigrationList()
    for i:=0; i<len(migrations); i++ {
        migrations[i].Run(ctx)
    }
}
