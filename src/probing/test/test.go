package test

import (
	"bufio"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	targetBandwidthMbps = 100.0
	maxWorkers          = 100_000
	initialWorkers      = 1000
	bitsPerProbe        = 6720
)

var (
	mu             sync.Mutex
	totalProbes    int
	validProbes    int
	totalIPs       int
	currentWorkers = initialWorkers
	ipChan         chan string
	wg             sync.WaitGroup
)

func Main(csvFile string) {
	f, err := os.Open(csvFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		// skip header
	}

	// Count total IPs
	for scanner.Scan() {
		if scanner.Text() != "" {
			totalIPs++
		}
	}

	// Reset scanner
	f.Seek(0, 0)
	scanner = bufio.NewScanner(f)
	if scanner.Scan() {
		// skip header
	}

	if totalIPs < currentWorkers {
		currentWorkers = totalIPs
	}

	ipChan = make(chan string, 10_000)

	// Start initial workers
	for i := 0; i < currentWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	// Start statistics goroutine
	go logStatistics()

	// Send IPs to channel
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 1 {
			continue
		}
		ipChan <- fields[0]
	}
	close(ipChan)
	wg.Wait()
}

func worker() {
	defer wg.Done()
	for ip := range ipChan {
		probeTarget(ip)
	}
}

func probeTarget(ip string) {
	delay := time.Duration(30+rand.Intn(771)) * time.Millisecond
	time.Sleep(delay)

	valid := rand.Float32() > 0.1
	updateStats(valid)
}

func updateStats(valid bool) {
	mu.Lock()
	defer mu.Unlock()
	totalProbes++
	if valid {
		validProbes++
	}
}

func logStatistics() {
	startTime := time.Now()
	lastProbes := 0
	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		mu.Lock()

		// Fortschritt
		probedPercentage := float64(totalProbes) / float64(totalIPs) * 100
		validPercentage := 0.0
		if totalProbes > 0 {
			validPercentage = float64(validProbes) / float64(totalProbes) * 100
		}

		// Restlaufzeit
		elapsed := time.Since(startTime)
		remainingTime := time.Duration(0)
		if totalProbes > 0 {
			remainingTime = time.Duration(float64(elapsed) / float64(totalProbes) * float64(totalIPs-totalProbes))
		}

		days := int(remainingTime.Hours()) / 24
		hours := int(remainingTime.Hours()) % 24
		minutes := int(remainingTime.Minutes()) % 60
		seconds := int(remainingTime.Seconds()) % 60

		timeLeft := ""
		if days > 0 {
			timeLeft += fmt.Sprintf("%dd", days)
		}
		if hours > 0 {
			timeLeft += fmt.Sprintf("%02dh", hours)
		}
		if minutes > 0 {
			timeLeft += fmt.Sprintf("%02dm", minutes)
		}
		if seconds > 0 || timeLeft == "" {
			timeLeft += fmt.Sprintf("%02ds", seconds)
		}

		// Bandbreite berechnen
		deltaProbes := totalProbes - lastProbes
		lastProbes = totalProbes
		bitsSent := deltaProbes * bitsPerProbe
		mbps := float64(bitsSent) / 1_000_000.0

		// Dynamische Anpassung
		diff := mbps - targetBandwidthMbps
		factor := diff / targetBandwidthMbps

		if factor < -0.1 {
			adjust := int(math.Round(float64(currentWorkers) * -factor))
			addWorkers(adjust)
		} else if factor > 0.1 {
			adjust := int(math.Round(float64(currentWorkers) * factor))
			removeWorkers(adjust)
		}

		fmt.Printf("estimated_time_left=[%s] probed_ip_addresses=[%d, %.2f%%] valid_probes=[%d, %.2f%%] used_bandwidth=[%.2f Mbps] workers=[%d]\n",
			timeLeft, totalProbes, probedPercentage, validProbes, validPercentage, mbps, currentWorkers)

		mu.Unlock()
	}
}

func addWorkers(n int) {
	for i := 0; i < n; i++ {
		wg.Add(1)
		go worker()
	}
	currentWorkers = int(math.Min(float64(currentWorkers+n), float64(maxWorkers)))
}

func removeWorkers(n int) {
	for i := 0; i < n; i++ {
		ipChan <- "" // leere IPs als Stop-Signal
	}
	currentWorkers = int(math.Max(float64(currentWorkers-n), 1.0))
}
