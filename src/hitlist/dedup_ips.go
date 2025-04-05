package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

const bitsetSize = 1 << 29 // 512 MB

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run dedup_ipv4.go <targets_file>")
		return
	}

	inputFile := os.Args[1]
	tempFile := inputFile + ".dedup_tmp"

	bitset := make([]byte, bitsetSize)

	inFile, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer inFile.Close()

	// Count the total number of IP addresses in the file
	var totalIPs int
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		totalIPs++
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

	// Reset scanner and open output file
	inFile.Seek(0, 0)
	outFile, err := os.Create(tempFile)
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	firstLine := true

	// Start timer for deduplication process
	startTime := time.Now()

	// Deduplication process
	var uniqueIPs int
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			firstLine = false
			continue // skip CSV header
		}

		ip := net.ParseIP(line).To4()
		if ip == nil {
			continue
		}

		idx := binary.BigEndian.Uint32(ip)
		byteIdx, bitIdx := idx/8, idx%8
		if bitset[byteIdx]&(1<<bitIdx) == 0 {
			bitset[byteIdx] |= 1 << bitIdx
			writer.WriteString(ip.String() + "\n")
			uniqueIPs++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input file:", err)
		return
	}

	writer.Flush()

	// Replace input file with deduplicated output
	if err := os.Rename(tempFile, inputFile); err != nil {
		fmt.Println("Error replacing original file:", err)
		return
	}

	// End timer
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Output results
	fmt.Printf("Total IPs before deduplication: %d\n", totalIPs)
	fmt.Printf("Total unique IPs after deduplication: %d\n", uniqueIPs)
	fmt.Printf("Total removed IPs: %d\n", totalIPs-uniqueIPs)
	fmt.Printf("Deduplication took: %s\n", duration)
}
