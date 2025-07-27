package snmp_scanner

import (
	"bufio"
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

type SNMPResponse struct {
	IP       string
	SysDescr string
}

// SNMP ASN.1 BER encoding helpers
func encodeBERLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	// For longer lengths, we need extended form
	var lengthBytes []byte
	temp := length
	for temp > 0 {
		lengthBytes = append([]byte{byte(temp & 0xFF)}, lengthBytes...)
		temp >>= 8
	}

	return append([]byte{0x80 | byte(len(lengthBytes))}, lengthBytes...)
}

func createSNMPGetRequest(community string, requestID uint32) []byte {
	// OID for sysDescr.0 (1.3.6.1.2.1.1.1.0)
	oid := []byte{
		0x06, 0x08, // OID type and length
		0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // 1.3.6.1.2.1.1.1.0
	}

	// Variable binding (OID + NULL value)
	varBind := append([]byte{0x30}, encodeBERLength(len(oid)+2)...)
	varBind = append(varBind, oid...)
	varBind = append(varBind, 0x05, 0x00) // NULL value

	// Variable binding list
	varBindList := append([]byte{0x30}, encodeBERLength(len(varBind))...)
	varBindList = append(varBindList, varBind...)

	// PDU (Protocol Data Unit) for GetRequest
	pdu := []byte{
		0xa0, // GetRequest PDU type
	}

	// PDU content: request-id, error-status, error-index, variable-bindings
	requestIDBytes := []byte{
		0x02, 0x04, // INTEGER, length 4
		byte(requestID >> 24), byte(requestID >> 16), byte(requestID >> 8), byte(requestID),
	}

	errorStatus := []byte{0x02, 0x01, 0x00} // INTEGER 0 (no error)
	errorIndex := []byte{0x02, 0x01, 0x00}  // INTEGER 0 (no error)

	pduContent := append(requestIDBytes, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varBindList...)

	pdu = append(pdu, encodeBERLength(len(pduContent))...)
	pdu = append(pdu, pduContent...)

	// Community string
	communityBytes := append([]byte{0x04}, encodeBERLength(len(community))...)
	communityBytes = append(communityBytes, []byte(community)...)

	// Version (SNMPv2c = 1)
	version := []byte{0x02, 0x01, 0x01}

	// Complete SNMP message
	messageContent := append(version, communityBytes...)
	messageContent = append(messageContent, pdu...)

	message := append([]byte{0x30}, encodeBERLength(len(messageContent))...)
	message = append(message, messageContent...)

	return message
}

func parseBERLength(data []byte, offset int) (int, int) {
	if offset >= len(data) {
		return 0, offset
	}

	firstByte := data[offset]
	offset++

	if firstByte < 0x80 {
		return int(firstByte), offset
	}

	lengthBytes := int(firstByte & 0x7F)
	if lengthBytes == 0 || offset+lengthBytes > len(data) {
		return 0, offset
	}

	length := 0
	for i := 0; i < lengthBytes; i++ {
		length = (length << 8) | int(data[offset+i])
	}

	return length, offset + lengthBytes
}

func parseSNMPResponse(data []byte) (string, error) {
	if len(data) < 10 {
		return "", fmt.Errorf("response too short")
	}

	offset := 0

	// Parse outer SEQUENCE
	if data[offset] != 0x30 {
		return "", fmt.Errorf("invalid SNMP message")
	}
	offset++

	_, offset = parseBERLength(data, offset)

	// Skip version
	if offset >= len(data) || data[offset] != 0x02 {
		return "", fmt.Errorf("invalid version")
	}
	offset++
	versionLen, newOffset := parseBERLength(data, offset)
	offset = newOffset + versionLen

	// Skip community
	if offset >= len(data) || data[offset] != 0x04 {
		return "", fmt.Errorf("invalid community")
	}
	offset++
	communityLen, newOffset := parseBERLength(data, offset)
	offset = newOffset + communityLen

	// Parse PDU
	if offset >= len(data) || data[offset] != 0xa2 { // GetResponse
		return "", fmt.Errorf("not a GetResponse")
	}
	offset++

	_, newOffset = parseBERLength(data, offset)
	offset = newOffset

	// Skip request-id, error-status, error-index (3 INTEGERs)
	for i := 0; i < 3; i++ {
		if offset >= len(data) || data[offset] != 0x02 {
			return "", fmt.Errorf("invalid PDU structure")
		}
		offset++
		intLen, newOffset := parseBERLength(data, offset)
		offset = newOffset + intLen
	}

	// Parse variable bindings
	if offset >= len(data) || data[offset] != 0x30 {
		return "", fmt.Errorf("invalid variable bindings")
	}
	offset++
	_, offset = parseBERLength(data, offset)

	// Parse first variable binding
	if offset >= len(data) || data[offset] != 0x30 {
		return "", fmt.Errorf("invalid variable binding")
	}
	offset++
	_, offset = parseBERLength(data, offset)

	// Skip OID
	if offset >= len(data) || data[offset] != 0x06 {
		return "", fmt.Errorf("invalid OID")
	}
	offset++
	oidLen, newOffset := parseBERLength(data, offset)
	offset = newOffset + oidLen

	// Parse value (should be OCTET STRING)
	if offset >= len(data) || data[offset] != 0x04 {
		return "", fmt.Errorf("invalid value type")
	}
	offset++

	valueLen, newOffset := parseBERLength(data, offset)
	offset = newOffset

	if offset+valueLen > len(data) {
		return "", fmt.Errorf("invalid value length")
	}

	return string(data[offset : offset+valueLen]), nil
}

func probeSNMP(ip string, community string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("udp", ip+":161", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set timeouts
	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	// Create and send SNMP request
	requestID := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	request := createSNMPGetRequest(community, requestID)

	_, err = conn.Write(request)
	if err != nil {
		return "", err
	}

	// Read response
	buffer := make([]byte, 1500) // Max UDP payload
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return parseSNMPResponse(buffer[:n])
}

func worker(ips <-chan string, results chan<- SNMPResponse, wg *sync.WaitGroup, processed *int64) {
	defer wg.Done()

	communities := []string{"public", "private", "community", "snmp"}

	for ip := range ips {
		var sysDescr string
		var err error

		// Try different community strings
		for _, community := range communities {
			sysDescr, err = probeSNMP(ip, community, 400*time.Millisecond)
			if err == nil && sysDescr != "" {
				break
			}
		}

		if err == nil && sysDescr != "" {
			// Clean description
			cleanDescr := strings.ReplaceAll(strings.TrimSpace(sysDescr), "\n", " ")
			if len(cleanDescr) > 200 { // Limit length
				cleanDescr = cleanDescr[:200] + "..."
			}
			results <- SNMPResponse{IP: ip, SysDescr: cleanDescr}
		}

		atomic.AddInt64(processed, 1)
	}
}

func fileWriter(results <-chan SNMPResponse, outPath string, done chan<- bool, successCount *int64) {
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

	writer.WriteString("IP,SNMP_OS_INFO\n")

	for result := range results {
		// Escape quotes in description
		escapedDescr := strings.ReplaceAll(result.SysDescr, "\"", "\"\"")
		writer.WriteString(fmt.Sprintf("%s,\"%s\"\n", result.IP, escapedDescr))
		atomic.AddInt64(successCount, 1)

		// Flush periodically
		if atomic.LoadInt64(successCount)%500 == 0 {
			writer.Flush()
		}
	}

	done <- true
}

func progressMonitor(processed *int64, total int64) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	start := time.Now()

	for range ticker.C {
		current := atomic.LoadInt64(processed)
		if current >= total {
			break
		}

		elapsed := time.Since(start).Seconds()
		rate := float64(current) / elapsed
		percentage := float64(current) / float64(total) * 100

		remaining := time.Duration((float64(total-current) / rate) * float64(time.Second))

		fmt.Printf("Progress: %d/%d (%.2f%%) - Rate: %.0f IPs/s - ETA: %v\n",
			current, total, percentage, rate, remaining)
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
	outPath := filepath.Join(dir, "snmp_os_info.csv.zst")

	// SNMP ist langsamer als SSH, weniger workers
	numWorkers := 800
	if runtime.NumCPU() < 8 {
		numWorkers = runtime.NumCPU() * 100
	}

	// Für sehr große Mengen: konservativer
	if totalIPs > 50000000 { // >50M IPs
		numWorkers = 600
	}

	fmt.Printf("Using %d workers\n", numWorkers)
	fmt.Printf("Trying communities: public, private, community, snmp\n")

	// Channels
	ips := make(chan string, numWorkers*2)
	results := make(chan SNMPResponse, 1000)
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
	fmt.Println("Starting SNMP scan...")
	go func() {
		defer close(ips)

		scanner := bufio.NewScanner(inputFile)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" && net.ParseIP(ip) != nil {
				ips <- ip
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %v\n", err)
		}
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(results)

	// Wait for file writer to finish
	<-done

	fmt.Printf("\nSNMP scan completed!\n")
	fmt.Printf("Output file: %s\n", outPath)
	fmt.Printf("Total processed: %d\n", atomic.LoadInt64(&processed))
	fmt.Printf("SNMP responses found: %d\n", atomic.LoadInt64(&successCount))

	// Calculate success rate
	successRate := float64(atomic.LoadInt64(&successCount)) / float64(atomic.LoadInt64(&processed)) * 100
	fmt.Printf("Success rate: %.2f%%\n", successRate)

	// Debug info
	fmt.Printf("\nDebug info:\n")
	fmt.Printf("- Tested communities: public, private, community, snmp\n")
	fmt.Printf("- OID queried: 1.3.6.1.2.1.1.1.0 (sysDescr.0)\n")
	fmt.Printf("- Timeout per request: 400ms\n")

	fmt.Println(outPath, processed, successCount)
}
