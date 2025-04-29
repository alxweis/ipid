package test

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	numWorkers = 10000
)

var (
	totalProbes int
	validProbes int
	totalIPs    int
	mu          sync.Mutex
)

func Main(csvFile string) {
	f, err := os.Open(csvFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Header überspringen
	if scanner.Scan() {
		// skip
	}

	// Zähle die Gesamtzahl der IPs
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		totalIPs++
	}

	// Scanner zurücksetzen, um die Datei erneut zu lesen
	f.Seek(0, 0)
	scanner = bufio.NewScanner(f)
	if scanner.Scan() {
		// skip Header
	}

	ipChan := make(chan string, numWorkers*10)
	var wg sync.WaitGroup

	// Workers starten
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ipChan, &wg)
	}

	// Statistik-Goroutine starten
	go logStatistics()

	// IPs lesen und an Channel schicken
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

func worker(ipChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range ipChan {
		probeTarget(ip)
	}
}

func probeTarget(ip string) {
	// Simuliere zufällige Verzögerung zwischen 30ms und 800ms
	// Simuliert die Zeit in der 10 ICMP Echo Requests gesendet und deren Replies empfangen werden
	delay := time.Duration(30+rand.Intn(771)) * time.Millisecond
	time.Sleep(delay)

	// Beispiel für eine gültige Probe
	valid := rand.Float32() > 0.1 // Angenommen, 90% der Pings sind gültig
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

	for {
		time.Sleep(1 * time.Second)
		mu.Lock()

		// Fortschritt
		probedPercentage := float64(totalProbes) / float64(totalIPs) * 100
		validPercentage := 0.0
		if totalProbes > 0 {
			validPercentage = float64(validProbes) / float64(totalProbes) * 100
		}

		// Restlaufzeit
		remainingTime := time.Duration(0)
		if totalProbes > 0 {
			elapsed := time.Since(startTime)
			remainingTime = time.Duration(float64(elapsed) / float64(totalProbes) * float64(totalIPs-totalProbes))
		}

		// Zeitformatierung
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

		// Bandbreite in Mbps (6720 Bit pro IP × Anzahl neue IPs in der letzten Sekunde)
		deltaProbes := totalProbes - lastProbes
		lastProbes = totalProbes
		bitsSent := deltaProbes * 6720
		mbps := float64(bitsSent) / 1_000_000.0 // in Megabit

		// Ausgabe
		fmt.Printf("estimated_time_left=[%s] probed_ip_addresses=[%d, %.2f%%] valid_probes=[%d, %.2f%%] used_bandwidth=[%.2f Mbps]\n",
			timeLeft, totalProbes, probedPercentage, validProbes, validPercentage, mbps)

		mu.Unlock()
	}
}

// Format the duration into hours, minutes, and seconds
func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%dh%dm%ds", h, m, s)
}
