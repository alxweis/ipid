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
	"unicode/utf16"

	"github.com/klauspost/compress/zstd"
)

type SMBResponse struct {
	IP     string
	OSInfo string
}

// SMBv1 Session Setup Request to get OS info
func createSMBv1SessionSetup() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x3E, // NetBIOS Session Service length
		// SMB Header
		0xFF, 0x53, 0x4D, 0x42, // Protocol ID (\xFFSMB)
		0x73,                   // Command: Session Setup AndX
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x01, 0x28, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID
		0x00, 0x00, // UID
		0x00, 0x00, // MID
		// Parameters (13 words = 26 bytes)
		0x0D,       // Word Count
		0xFF,       // AndXCommand: No further commands
		0x00,       // Reserved
		0x00, 0x00, // AndXOffset
		0xFF, 0xFF, // MaxBufferSize
		0x02, 0x00, // MaxMpxCount
		0x01, 0x00, // VCNumber
		0x00, 0x00, 0x00, 0x00, // SessionKey
		0x00, 0x00, // ANSI Password Length
		0x00, 0x00, // Unicode Password Length
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x40, 0x00, 0x00, 0x00, // Capabilities
		// Data
		0x00, 0x00, // Byte Count
	}
}

// SMBv1 Negotiate Protocol Request
func createSMBv1Negotiate() []byte {
	dialects := "\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02Windows for Workgroups 3.1a\x00\x02LM1.2X002\x00\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
	dialectsLen := len(dialects)

	header := []byte{
		0x00, 0x00, 0x00, byte(35 + dialectsLen), // NetBIOS length
		// SMB Header
		0xFF, 0x53, 0x4D, 0x42, // Protocol ID
		0x72,                   // Command: Negotiate Protocol
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x53, 0xC8, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // TID
		0x00, 0x00, // PID
		0x00, 0x00, // UID
		0x00, 0x00, // MID
		// Parameters
		0x00, // Word Count
		// Data
		byte(dialectsLen & 0xFF), byte(dialectsLen >> 8), // Byte Count
	}

	return append(header, []byte(dialects)...)
}

func probeSMB(ip string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", ip+":445", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	// Try SMBv1 first for OS info
	osInfo, err := probeSMBv1(conn, timeout)
	if err == nil && osInfo != "" {
		return osInfo, nil
	}

	// Fallback to SMBv2 for basic info
	return probeSMBv2(conn, timeout)
}

func probeSMBv1(conn net.Conn, timeout time.Duration) (string, error) {
	// Send Negotiate Protocol
	negotiate := createSMBv1Negotiate()
	_, err := conn.Write(negotiate)
	if err != nil {
		return "", err
	}

	// Read Negotiate Response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	// Check if SMBv1 is supported
	if n < 40 || string(buffer[4:8]) != "\xFF\x53\x4D\x42" {
		return "", fmt.Errorf("not SMBv1")
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	// Send Session Setup to get OS info
	sessionSetup := createSMBv1SessionSetup()
	_, err = conn.Write(sessionSetup)
	if err != nil {
		return "", err
	}

	// Read Session Setup Response
	n, err = conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return parseSMBv1OSInfo(buffer[:n])
}

func probeSMBv2(conn net.Conn, timeout time.Duration) (string, error) {
	// SMBv2 Negotiate
	request := []byte{
		0x00, 0x00, 0x00, 0x7c, // NetBIOS length
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

	_, err := conn.Write(request)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return parseSMB2Response(buffer[:n])
}

func parseSMBv1OSInfo(data []byte) (string, error) {
	if len(data) < 40 {
		return "", fmt.Errorf("response too short")
	}

	// Check SMB signature
	if string(data[4:8]) != "\xFF\x53\x4D\x42" {
		return "", fmt.Errorf("not SMBv1 response")
	}

	// Check if it's a Session Setup AndX Response (0x73)
	if data[8] != 0x73 {
		return "SMBv1 (No OS Info)", nil
	}

	// Skip to parameters section
	if len(data) < 37 {
		return "SMBv1", nil
	}

	wordCount := data[36]
	if wordCount < 3 {
		return "SMBv1", nil
	}

	// Skip parameters to get to data section
	dataOffset := 37 + int(wordCount)*2
	if len(data) <= dataOffset+2 {
		return "SMBv1", nil
	}

	// Read byte count
	byteCount := binary.LittleEndian.Uint16(data[dataOffset : dataOffset+2])
	dataStart := dataOffset + 2

	if len(data) < dataStart+int(byteCount) {
		return "SMBv1", nil
	}

	// Parse strings from data section
	osInfo := extractSMBv1Strings(data[dataStart : dataStart+int(byteCount)])
	if osInfo != "" {
		return osInfo, nil
	}

	return "SMBv1", nil
}

func extractSMBv1Strings(data []byte) string {
	var result []string
	i := 0

	// Extract up to 3 null-terminated strings (Native OS, Native LAN Manager, Primary Domain)
	for stringNum := 0; stringNum < 3 && i < len(data); stringNum++ {
		start := i

		// Find null terminator
		for i < len(data) && data[i] != 0 {
			i++
		}

		if i > start {
			str := string(data[start:i])
			if strings.TrimSpace(str) != "" {
				result = append(result, strings.TrimSpace(str))
			}
		}

		// Skip null terminator
		if i < len(data) && data[i] == 0 {
			i++
		}
	}

	if len(result) > 0 {
		return strings.Join(result, " | ")
	}

	return ""
}

func parseSMB2Response(data []byte) (string, error) {
	if len(data) < 16 {
		return "", fmt.Errorf("response too short")
	}

	// Check for SMB2 magic
	if string(data[4:8]) != "\xfe\x53\x4d\x42" {
		return "", fmt.Errorf("not SMB2 response")
	}

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

func utf16ToString(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert UTF-16 to UTF-8
	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(data[i*2:])
	}

	return string(utf16.Decode(u16s))
}

func worker(ips <-chan string, results chan<- SMBResponse, wg *sync.WaitGroup, processed *int64) {
	defer wg.Done()

	for ip := range ips {
		osInfo, err := probeSMB(ip, 1200*time.Millisecond) // Longer timeout for OS detection
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
		// Escape quotes in OS info
		escaped := strings.ReplaceAll(result.OSInfo, "\"", "\"\"")
		writer.WriteString(fmt.Sprintf("%s,\"%s\"\n", result.IP, escaped))
		atomic.AddInt64(successCount, 1)

		if atomic.LoadInt64(successCount)%500 == 0 {
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

	// Reduce workers for SMBv1 OS detection (more intensive)
	numWorkers := 500
	if runtime.NumCPU() < 8 {
		numWorkers = runtime.NumCPU() * 50
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
	fmt.Println("Starting SMB OS detection...")
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
