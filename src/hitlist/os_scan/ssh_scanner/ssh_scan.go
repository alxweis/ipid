package ssh_scanner

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

type SSHResponse struct {
	IP     string
	Banner string
}

func probeSSH(ip string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", ip+":22", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read SSH banner (meist erste Zeile)
	buffer := make([]byte, 512) // SSH banner sind normalerweise < 512 bytes
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	banner := string(buffer[:n])

	// Find first line (SSH banner)
	lines := strings.Split(banner, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "SSH-") {
		// Clean banner: remove SSH- prefix and normalize
		cleanBanner := strings.TrimSpace(lines[0])
		return parseSSHBanner(cleanBanner), nil
	}

	return "", fmt.Errorf("no valid SSH banner")
}

func parseSSHBanner(banner string) string {
	// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
	// SSH-2.0-OpenSSH_7.4
	// SSH-2.0-libssh_0.8.9

	parts := strings.Split(banner, " ")
	if len(parts) >= 1 {
		// Extract SSH version and software info
		software := parts[0] // SSH-2.0-OpenSSH_8.2p1
		if strings.Contains(software, "-") {
			softwareParts := strings.Split(software, "-")
			if len(softwareParts) >= 3 {
				version := softwareParts[2] // OpenSSH_8.2p1
				osInfo := ""

				// Extract OS info from additional parts
				if len(parts) > 1 {
					osInfo = strings.Join(parts[1:], " ")
				}

				if osInfo != "" {
					return fmt.Sprintf("%s (%s)", version, osInfo)
				}
				return version
			}
		}
	}

	// Fallback: return cleaned banner
	return strings.TrimPrefix(banner, "SSH-2.0-")
}

func worker(ips <-chan string, results chan<- SSHResponse, wg *sync.WaitGroup, processed *int64) {
	defer wg.Done()

	for ip := range ips {
		banner, err := probeSSH(ip, 300*time.Millisecond)
		if err == nil && banner != "" {
			results <- SSHResponse{IP: ip, Banner: banner}
		}
		atomic.AddInt64(processed, 1)
	}
}

func fileWriter(results <-chan SSHResponse, outPath string, done chan<- bool, successCount *int64) {
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

	writer.WriteString("IP,SSH_OS_INFO\n")

	for result := range results {
		// Escape quotes in banner
		escapedBanner := strings.ReplaceAll(result.Banner, "\"", "\"\"")
		writer.WriteString(fmt.Sprintf("%s,\"%s\"\n", result.IP, escapedBanner))
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
		rate := float64(current) / 10.0 // IPs per second (approximation)
		fmt.Printf("Progress: %d/%d (%.2f%%) - Rate: %.0f IPs/s\n",
			current, total, percentage, rate)
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
	outPath := filepath.Join(dir, "ssh_os_info.csv.zst")

	// Calculate optimal goroutine count
	// SSH ist schneller als SMB, daher mehr workers möglich
	numWorkers := 2000
	if runtime.NumCPU() < 8 {
		numWorkers = runtime.NumCPU() * 200
	}

	// Für sehr große Mengen: limit basierend auf RAM
	if totalIPs > 50000000 { // >50M IPs
		numWorkers = 1500
	}

	fmt.Printf("Using %d workers\n", numWorkers)

	// Channels
	ips := make(chan string, numWorkers*2)
	results := make(chan SSHResponse, 2000)
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

	// Read and send IPs with batching for better memory efficiency
	fmt.Println("Starting SSH banner scan...")
	go func() {
		defer close(ips)

		scanner := bufio.NewScanner(inputFile)
		// Set larger buffer für bessere IO performance
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" && net.ParseIP(ip) != nil { // Basic IP validation
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

	fmt.Printf("\nSSH scan completed!\n")
	fmt.Printf("Output file: %s\n", outPath)
	fmt.Printf("Total processed: %d\n", atomic.LoadInt64(&processed))
	fmt.Printf("SSH banners found: %d\n", atomic.LoadInt64(&successCount))

	// Calculate success rate
	successRate := float64(atomic.LoadInt64(&successCount)) / float64(atomic.LoadInt64(&processed)) * 100
	fmt.Printf("Success rate: %.2f%%\n", successRate)

	fmt.Println(outPath, processed, successCount)
}
