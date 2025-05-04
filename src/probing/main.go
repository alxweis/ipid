package main

import (
	"fmt"
	"ipid/common"
	"os"
)

func main() {
	//test.Main("../../targets/tcp/80/2025-04-20_19-05-04/targets.csv")
	if len(os.Args) != 2 {
		fmt.Println("Error: Mode not specified")
		return
	}
	mode := os.Args[1]
	common.Main(mode)
}
