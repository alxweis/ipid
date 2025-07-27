package smb_scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

type SMBResponse struct {
	IP     string
	OSInfo string
}

// SMB Negotiate Protocol Request (SMBv1/v2)
func createSMBNegotiateRequest() []byte {
	// SMBv2 Negotiate Request
	return []byte{
		0x00, 0x00, 0x00, 0x7c, // NetBIOS Session Service length
		0xfe, 0x53, 0x4d, 0x42, // SMB2 Protocol ID
		0x40, 0x00, // Structure Size
		0x00, 0x00, // Credit Charge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command - Negotiate
		0x01, 0x00, // Credit Request
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next Command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x24, 0x00, // Structure Size
		0x02, 0x00, // Dialect Count
		0x00, 0x00, // Security Mode
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Negotiate Context
		0x02, 0x02, // SMB 2.0.2
		0x10, 0x02, // SMB 2.1
	}
}

func probeSMB(ip string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", ip+":445", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	// Send SMB negotiate request
	request := createSMBNegotiateRequest()
	_, err = conn.Write(request)
	if err != nil {
		return "", err
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return parseSMBResponse(buffer[:n])
}

func parseSMBResponse(data []byte) (string, error) {
	if len(data) < 16 {
		return "", fmt.Errorf("response too short")
	}

	// Check for SMB2 magic
	if len(data) >= 8 && string(data[4:8]) == "\xfe\x53\x4d\x42" {
		return parseSMB2Response(data)
	}

	// Check for SMB1 magic
	if len(data) >= 8 && string(data[4:8]) == "\xff\x53\x4d\x42" {
		return "SMBv1", nil
	}

	return "Unknown SMB", nil
}

func parseSMB2Response(data []byte) (string, error) {
	if len(data) < 68 {
		return "SMBv2/3", nil
	}

	// Parse dialect revision from negotiate response
	if len(data) >= 72 {
		dialectRevision := binary.LittleEndian.Uint16(data[70:72])
		switch dialectRevision {
		case 0x0202:
			return "SMBv2.0.2", nil
		case 0x0210:
			return "SMBv2.1", nil
		case 0x0300:
			return "SMBv3.0", nil
		case 0x0302:
			return "SMBv3.0.2", nil
		case 0x0311:
			return "SMBv3.1.1", nil
		default:
			return fmt.Sprintf("SMBv2/3 (0x%x)", dialectRevision), nil
		}
	}

	return "SMBv2/3", nil
}

func worker(ips <-chan string, results chan<- SMBResponse, wg *sync.WaitGroup, processed *int64) {
	defer wg.Done()

	for ip := range ips {
		osInfo, err := probeSMB(ip, 800*time.Millisecond)
		if err == nil && osInfo != "" {
			results <- SMBResponse{IP: ip, OSInfo: osInfo}
		}
		atomic.AddInt64(processed, 1)
	}
}

func fileWriter(results <-chan SMBResponse, outPath string, done chan<- bool, successCount *int64) {
	outFile, err := os.Create(outPath)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	encoder, err := zstd.NewWriter(outFile)
	if err != nil {
		panic(err)
	}
	defer encoder.Close()

	writer := bufio.NewWriter(encoder)
	defer writer.Flush()

	writer.WriteString("IP,SMB_OS_INFO\n")

	for result := range results {
		writer.WriteString(fmt.Sprintf("%s,\"%s\"\n", result.IP, result.OSInfo))
		atomic.AddInt64(successCount, 1)

		// Flush periodically to avoid memory buildup
		if atomic.LoadInt64(successCount)%1000 == 0 {
			writer.Flush()
		}
	}

	done <- true
}

func progressMonitor(processed *int64, total int64) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		current := atomic.LoadInt64(processed)
		if current >= total {
			break
		}
		percentage := float64(current) / float64(total) * 100
		fmt.Printf("Progress: %d/%d (%.2f%%)\n", current, total, percentage)
	}
}

func countLines(filePath string) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var count int64
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

func Main(inputPath string) {
	// Count total lines for progress monitoring
	fmt.Println("Counting IPs...")
	totalIPs, err := countLines(inputPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Total IPs to process: %d\n", totalIPs)

	inputFile, err := os.Open(inputPath)
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	dir := filepath.Dir(inputPath)
	outPath := filepath.Join(dir, "smb_os_info.csv.zst")

	// Calculate optimal goroutine count based on available memory
	// Für <1.3GB RAM: konservativ 1000 workers
	numWorkers := 1000
	if runtime.NumCPU() < 8 {
		numWorkers = runtime.NumCPU() * 100
	}

	// Channels
	ips := make(chan string, numWorkers*2)
	results := make(chan SMBResponse, 1000)
	done := make(chan bool)

	// Counters
	var processed int64
	var successCount int64

	// Start file writer
	go fileWriter(results, outPath, done, &successCount)

	// Start progress monitor
	go progressMonitor(&processed, totalIPs)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ips, results, &wg, &processed)
	}

	// Read and send IPs
	fmt.Println("Starting SMB scan...")
	go func() {
		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				ips <- ip
			}
		}
		close(ips)
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(results)

	// Wait for file writer to finish
	<-done

	fmt.Printf("\nScan completed!\n")
	fmt.Printf("Output file: %s\n", outPath)
	fmt.Printf("Total processed: %d\n", atomic.LoadInt64(&processed))
	fmt.Printf("SMB responses: %d\n", atomic.LoadInt64(&successCount))

	fmt.Println(outPath, processed, successCount)
}
