package main

import (
	"fmt"
	"ipid/b2b"
	"ipid/seq"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Error: Mode not specified")
		return
	}
	mode := os.Args[1]
	switch mode {
	case "b2b":
		b2b.Main()
	case "seq":
		seq.Main()
	default:
		fmt.Println("Unknown mode:", mode)
	}
}
