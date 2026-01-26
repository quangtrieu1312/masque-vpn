package migration

import (
    "fmt"
)

type Migration3 struct {
    Version string
    Description string
}

func (m Migration3) Run() int {
    m.Description = "test 03"
    fmt.Sprintf("%v", m.Description)
    return 0
}
