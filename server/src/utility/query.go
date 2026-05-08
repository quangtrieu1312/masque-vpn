package utility

import (
    "fmt"
    "strings"
)

func Int64sInCSVFormat(values ...int64) string {
	var b strings.Builder
	for i, v := range values {
		if i != 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%d", v)
	}
	return b.String()
}

func Int64ArrayInCSVFormat(values []int64) string {
	var b strings.Builder
	for i, v := range values {
		if i != 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%d", v)
	}
	return b.String()
}
