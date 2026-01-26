package migration

import (
    "fmt"
)

type Migration2 struct {
    Version string
    Description string
}

func (m Migration2) Run() int {
    fmt.Sprintf("%v", m.Description)
    return 0
}
