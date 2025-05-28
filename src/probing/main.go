package main

import (
	"fmt"
	"ipid/base"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Error: Mode or TargetsType not specified")
		return
	}
	mode := os.Args[1]
	targetsType := os.Args[2]
	base.Main(mode, targetsType)
}
