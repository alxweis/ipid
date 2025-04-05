package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

func removeDuplicateIPsInPlace(inputFile string) error {
	//Create a temporary file
	tmpFile, err := os.CreateTemp("", "deduped-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFileName := tmpFile.Name()
	defer os.Remove(tmpFileName) // cleanup temp file on exit
	defer tmpFile.Close()

	// Open the input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	reader := bufio.NewReader(inFile)

	// Read and write the header , the original header is required to restore original csv
	header, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read header row: %w", err)
	}
	_, err = tmpFile.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write header to temporary file: %w", err)
	}

	// Run sort on the rest of the inputfile content, skipping the header
	cmd := exec.Command("sort", "-u")
	cmd.Stdin = reader
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

	// write the sorted content into the temporary file
	writer := bufio.NewWriter(tmpFile)
	defer writer.Flush()
	scanner := bufio.NewScanner(sortedOutput)

	for scanner.Scan() {
		line := scanner.Text()
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to temporary file: %w", err)
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

	err = inFile.Close()
	if err != nil {
		return fmt.Errorf("failed closing input file: %w", err)
	}
	// Replace the original file with the temporary file
	err = os.Rename(tmpFileName, inputFile)
	if err != nil {
		return fmt.Errorf("failed to replace original file with temporary file: %w", err)
	}

	fmt.Printf("Duplicate IP addresses removed and saved back to '%s'\n", inputFile)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run cleanup.go <targets_file>")
		os.Exit(1)
	}
	inputFile := os.Args[1]

	err := removeDuplicateIPsInPlace(inputFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
