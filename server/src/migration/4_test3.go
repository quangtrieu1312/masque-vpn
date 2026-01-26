package migration

import (
    "fmt"
)

type Migration4 struct {
    Description string
}

func (m Migration4) Run() int {
    m.Description = "test 02"
    fmt.Sprintf("%v", m.Description)
    return 0
}
