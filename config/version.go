package config

import "fmt"

var commit string
var tag string

func Version() string {
	return fmt.Sprintf("%s (%s)", tag, commit)
}
