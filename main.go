package main

import (
	"ztools/tools"
)

func main() {
	go tools.Portscan()
	tools.Subnetscan()
}
