package main

import (
	"fmt"
	"ipid/base"
	"os"
)

func main() {
	//test.Main("../../targets/tcp/80/2025-04-20_19-05-04/targets.csv")
	if len(os.Args) != 2 {
		fmt.Println("Error: Mode not specified")
		return
	} else if len(os.Args) != 3 {
		fmt.Println("Error: targetsType not specified")
		return
	}
	mode := os.Args[1]
	targetsType := os.Args[2]
	base.Main(mode, targetsType)
}
