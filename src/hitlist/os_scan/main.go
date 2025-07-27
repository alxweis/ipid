package main

import (
	"fmt"
	"hitlist/os_scan/smb_scanner"
	"hitlist/os_scan/snmp_scanner"
	"hitlist/os_scan/ssh_scanner"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Error: Mode or InputPath not specified")
		return
	}
	mode := os.Args[1]
	inputPath := os.Args[2]

	switch mode {
	case "snmp":
		snmp_scanner.Main(inputPath)
	case "ssh":
		ssh_scanner.Main(inputPath)
	case "smb":
		smb_scanner.Main(inputPath)
	default:
		fmt.Println("Unknown mode:", mode)
	}
}
