package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

func removeDuplicateIPs(inputFile, outputFile string) error {
	// 1. Sort the input file using the 'sort' command.  The '-u' option tells sort to only output unique lines
	cmd := exec.Command("sort", "-u", inputFile)
	sortedOutput, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe for sort: %w", err)
	}
	cmdErr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to open stderr pipe for sort: %w", err)
	}

	err = cmd.Start()
	if err != nil {
		errContent, _ := io.ReadAll(cmdErr)
		return fmt.Errorf("failed to start sort command: %w, sort standarderror shows: %s", err, string(errContent))
	}

	// 2. Process the sorted output, writing unique lines to the output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	scanner := bufio.NewScanner(sortedOutput)
	for scanner.Scan() {
		line := scanner.Text()
		_, err := writer.WriteString(line + "\n") // Add newline back
		if err != nil {
			return fmt.Errorf("failed to write to output file: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading sorted output: %w", err)
	}

	err = cmd.Wait()

	if err != nil {
		errContent, _ := io.ReadAll(cmdErr)
		return fmt.Errorf("sort command finished with error: %w, sort standarderror shows: %s", err, string(errContent))
	}

	fmt.Printf("Duplicate IP addresses removed and saved to '%s'\n", outputFile)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run cleanup.go <targets_file>")
		os.Exit(1)
	}
	inputFile := os.Args[1]
	outputFile := "output.csv"

	err := removeDuplicateIPs(inputFile, outputFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
