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
	// 1. Read the header from the input file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	reader := bufio.NewReader(inFile)
	header, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// 2. Create the output file and write the header
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	_, err = outFile.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write header to output file: %w", err)
	}

	// 3. Create a temporary file for the body (without header) to be sorted
	tmpFile, err := os.CreateTemp("", "sorted-body-")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up after
	defer tmpFile.Close()

	// Copy the rest of the input file (without header) to the temp file
	_, err = io.Copy(tmpFile, reader)
	if err != nil {
		return fmt.Errorf("failed to copy remaining data to temporary file: %w", err)
	}

	// 4. Sort the temporary file using the 'sort' command
	cmd := exec.Command("sort", "-u", tmpFile.Name())
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

	// 5. Process the sorted output and append to output file
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
