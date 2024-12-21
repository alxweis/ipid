package main

import (
	"ipid_analysis/probing/fast"
	"ipid_analysis/probing/slow"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Println("Usage: sudo go run probing.go (fast|slow)")
		return
	}

	mode := os.Args[1]
	switch mode {
	case "fast":
		probing_fast.Main()
	case "slow":
		probing_slow.Main()
	default:
		log.Println("Usage: sudo go run probing.go (fast|slow)")
	}
}
