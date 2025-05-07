package common

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/breml/bpfutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/ilyakaznacheev/cleanenv"
	"golang.org/x/net/ipv4"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

import _ "net/http/pprof"

type ProbingMode interface {
	createOutputDir(basePath string) string
	createRawIPLayers() []layers.IPv4
	probeTarget(target string)
}

type ProbingVars struct {
	retryCount   uint16
	requestCount uint16
	dirName      string
}

type B2B struct {
	ProbingVars
	requestInterval time.Duration
}

func (pm B2B) createOutputDir(basePath string) string {
	return pm.ProbingVars.createOutputDir(basePath)
}

func (pm B2B) createRawIPLayers() []layers.IPv4 {
	return pm.ProbingVars.createRawIPLayers()
}

type SEQ struct {
	ProbingVars
}

func (pm SEQ) createOutputDir(basePath string) string {
	return pm.ProbingVars.createOutputDir(basePath)
}

func (pm SEQ) createRawIPLayers() []layers.IPv4 {
	return pm.ProbingVars.createRawIPLayers()
}

type Config struct {
	Targets              string         `yaml:"targets"`
	Protocol             string         `yaml:"protocol"`
	RecTraffic           bool           `yaml:"record_traffic"`
	TcpDstPort           layers.TCPPort `yaml:"tcp_dst_port"`
	TcpReqFlags          string         `yaml:"tcp_request_flags"`
	TcpSrcPortOffset     uint16         `yaml:"tcp_src_port_offset"`
	UdpDstPort           layers.UDPPort `yaml:"udp_dst_port"`
	UdpSrcPortOffset     uint16         `yaml:"udp_src_port_offset"`
	B2BReqCount          uint16         `yaml:"b2b_request_count"`
	B2BReqInterval       time.Duration  `yaml:"b2b_request_interval"`
	B2BRetryCount        uint16         `yaml:"b2b_retry_count"`
	SEQReqCount          uint16         `yaml:"seq_request_count"`
	SEQRetryCount        uint16         `yaml:"seq_retry_count"`
	IfaceA               Iface          `yaml:"iface_a"`
	IfaceB               Iface          `yaml:"iface_b"`
	MaxRTT               time.Duration  `yaml:"max_rtt"`
	SendBandwidth        string         `yaml:"send_bandwidth"`
	DefaultSendIpIds     []uint16       `yaml:"default_send_ip_ids"`
	DetectReflectedIpIds bool           `yaml:"detect_reflected_ip_ids"`
	ReflectionSendIpIds  []uint16       `yaml:"reflection_send_ip_ids"`
	IpColName            string         `yaml:"ip_col_name"`
	IpIdSeqColName       string         `yaml:"ip_id_seq_col_name"`
	SendTsColName        string         `yaml:"send_ts_seq_col_name"`
	RecvTsColName        string         `yaml:"received_ts_seq_col_name"`
	CheckSeqColName      string         `yaml:"check_seq_col_name"`
}

type Iface struct {
	Name string `yaml:"name"`
	Ip   string `yaml:"ip"`
}

type ProbePoint struct {
	IpId         uint16
	SentTime     int64
	ReceivedTime int64
	Check        bool
}

type Probe struct {
	IPAddr string
	Data   map[uint16]*ProbePoint
}

type ReplyInfo struct {
	Packet gopacket.Packet
	Time   int64
}

type Protocol struct {
	Id           string
	Filter       string
	IpLayer      layers.IPProtocol
	CreateLayers func(ipLayers []layers.IPv4, requestCount uint16) ([][]byte, int)
	CheckLayer   func(packet gopacket.Packet, requestCount uint16) (bool, uint16)
}

type Sender struct {
	EthHeader []byte
	Fd        int
	Addr      syscall.SockaddrLinklayer
}

var (
	ICMP = &Protocol{
		Id:           "icmp",
		Filter:       "icmp[icmptype] == icmp-echoreply",
		IpLayer:      layers.IPProtocolICMPv4,
		CreateLayers: createICMPLayers,
		CheckLayer:   checkICMPLayer,
	}
	TCP = &Protocol{
		Id:           "tcp",
		Filter:       "",
		IpLayer:      layers.IPProtocolTCP,
		CreateLayers: createTCPLayers,
		CheckLayer:   checkTCPLayer,
	}
	UDP = &Protocol{
		Id:           "udp",
		Filter:       "",
		IpLayer:      layers.IPProtocolUDP,
		CreateLayers: createUDPLayers,
		CheckLayer:   checkUDPLayer,
	}
)

const (
	maxWorkers       = 2000
	workerStopSignal = "STOP_WORKER"
)

var (
	pm                 ProbingMode
	config             Config
	srcAIp             net.IP
	srcBIp             net.IP
	workerWg           sync.WaitGroup
	recvWg             sync.WaitGroup
	saveWg             sync.WaitGroup
	stopReceiving      = make(chan struct{})
	probeBuffer        = make(map[string]*Probe)
	probeBufferMu      sync.RWMutex
	probeSaveChan      = make(chan *Probe)
	recvChans          sync.Map
	opts               = gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	recordingProcesses []*exec.Cmd
	totalTargetCount   int
	totalProbes        int
	deltaByteSize      int
	validProbes        int
	targetSendMbps     int
	currentWorkers     = 1
	targetChan         = make(chan string, maxWorkers*2)
	senderA            *Sender
	senderB            *Sender
	rawIPLayers        []layers.IPv4
	proto              *Protocol
	statsMu            sync.Mutex
)

func Main(mode string) {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	runtime.GOMAXPROCS(runtime.NumCPU()) // Utilize all available CPUs

	// Load configuration
	loadConfig()

	// Load probing mode
	loadProbingMode(mode)

	basePath := getBasePath()
	outputDir := pm.createOutputDir(basePath)

	// Load targets file
	targetsFile := loadTargets(config.Targets, basePath, outputDir)

	// Load protocol and raw IP layers
	proto = loadProtocol(config.Protocol)
	rawIPLayers = pm.createRawIPLayers()

	// Setup senders
	senderA = setupSender(config.IfaceA)
	senderB = setupSender(config.IfaceB)

	// Start saving probes
	saveWg.Add(1)
	go saveProbes(outputDir)

	// Start recording if enabled
	if config.RecTraffic {
		startRecording(outputDir)
	}

	// Block auto-send RST when using TCP
	var rstChanged bool
	if proto.Id == "tcp" {
		rstChanged = setRSTDrop(true)
	}

	// Start receivers
	recvWg.Add(2)
	go setupReceiver(config.IfaceA)
	go setupReceiver(config.IfaceB)

	// Open targets file
	f, err := os.Open(targetsFile)
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		err = f.Close()
		if err != nil {
			panic(err)
		}
	}(f)

	// Create a scanner and skip the header
	scanner := bufio.NewScanner(f)
	if scanner.Scan() { // Skip header line
	}

	// Count total targets
	for scanner.Scan() {
		if scanner.Text() != "" {
			totalTargetCount++
		}
	}

	// Reset scanner to read the file again
	_, err = f.Seek(0, 0)
	if err != nil {
		panic(err)
	}
	scanner = bufio.NewScanner(f)
	if scanner.Scan() { // Skip header line again
	}

	// Start initial workers
	for i := 0; i < currentWorkers; i++ {
		workerWg.Add(1)
		go worker()
	}

	// Start statistics goroutine
	go logStatistics()

	// Send targets to channel
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 1 {
			continue
		}
		targetChan <- fields[0] // Send target to channel TODO: Get index of "IP" column
	}

	// Now that all targets have been sent, close the targetChan
	close(targetChan)

	// Wait for workers to finish
	workerWg.Wait()

	// Close the probe save channel
	close(probeSaveChan)
	saveWg.Wait()

	// Close receiving channels and wait for them to finish
	close(stopReceiving)
	recvWg.Wait()

	// Stop recording if enabled
	if config.RecTraffic {
		stopRecording()
	}

	// Unblock auto-send RST when using TCP and changed
	if rstChanged {
		setRSTDrop(false)
	}

	// Log results
	log.Println("Results Directory:", outputDir)
}

// ProbePoint
func createProbePoint(probe *Probe, seq uint16, sentTime int64) *ProbePoint {
	pp := &ProbePoint{
		SentTime: sentTime,
	}
	probe.Data[seq] = pp
	return pp
}

// Probe
func createProbe(target string) *Probe {
	probe := &Probe{
		IPAddr: target,
		Data:   make(map[uint16]*ProbePoint),
	}
	probeBufferMu.Lock()
	probeBuffer[target] = probe
	probeBufferMu.Unlock()
	return probe
}

func removeProbe(target string) {
	probeBufferMu.Lock()
	delete(probeBuffer, target)
	probeBufferMu.Unlock()
}

// Worker
func worker() {
	defer workerWg.Done()
	for target := range targetChan {
		if target == workerStopSignal {
			break
		}
		pm.probeTarget(target)
	}
}

func addWorkers(n int) {
	n = clampInt(n, 0, maxWorkers-currentWorkers)
	for i := 0; i < n; i++ {
		workerWg.Add(1)
		go worker()
	}
	currentWorkers += n
}

func removeWorkers(n int) {
	n = clampInt(n, 0, currentWorkers-1)
	for i := 0; i < n; i++ {
		targetChan <- workerStopSignal
	}
	currentWorkers -= n
}

func clampInt(x, min, max int) int {
	if x < min {
		return min
	}
	if x > max {
		return max
	}
	return x
}

// Probing
func (pm SEQ) probeTarget(target string) {
	dstIP := net.ParseIP(target).To4()
	payloads, probeSentBytes := pm.buildPackets(rawIPLayers, dstIP)

	var isProbeValid bool
	var recvCounter uint16
	var retriesLeft uint16
	var recvCh chan *ReplyInfo
	var probe *Probe

	for retriesLeft = pm.retryCount; true; retriesLeft-- {
		probe = createProbe(target)
		recvCh = createRecvChan(target)
		recvCounter = 0
		for seq := uint16(0); seq < pm.requestCount; seq++ {
			sender, senderIP := getSender(seq)
			sendPacket(sender, payloads[seq], seq, probe)
			if pm.receivePacket(recvCh, target, senderIP.String(), seq, probe) {
				recvCounter++
			} else {
				break
			}
		}

		if recvCounter == pm.requestCount { // Found all replies
			isProbeValid = true
			break
		}
	}

	close(recvCh)
	deleteRecvChan(target)
	if isProbeValid {
		probeSaveChan <- probe
	}
	removeProbe(target)
	updateStats(isProbeValid, probeSentBytes)
	//log.Printf("Finished probing target=%s received=%d/%d sent_bytes=%d used_retries=%d", target, recvCounter, pm.requestCount, probeSentBytes, pm.retryCount-retriesLeft)
}

func (pm B2B) probeTarget(target string) {
	dstIP := net.ParseIP(target).To4()
	payloads, probeSentBytes := pm.buildPackets(rawIPLayers, dstIP)

	var isProbeValid bool
	var _ uint16
	var retriesLeft uint16
	var recvCh chan *ReplyInfo
	var probe *Probe

	for retriesLeft = pm.retryCount; true; retriesLeft-- {
		probe = createProbe(target)
		recvCh = createRecvChan(target)
		pm.sendPackets(payloads, probe)
		isProbeValid, _ = pm.receivePackets(recvCh, target, probe)
		if isProbeValid {
			break
		}
	}

	close(recvCh)
	deleteRecvChan(target)
	if isProbeValid {
		probeSaveChan <- probe
	}
	removeProbe(target)
	updateStats(isProbeValid, probeSentBytes)
	//log.Printf("Finished probing target=%s received=%d/%d sent_bytes=%d used_retries=%d", target, recvCounter, pm.requestCount, probeSentBytes, pm.retryCount-retriesLeft)
}

// Send
func setupSender(iface Iface) *Sender {
	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(err)
	}
	srcMac := ifc.HardwareAddr
	if len(srcMac) == 0 {
		panic("No Src MAC")
	}
	gwIp, err := getDefGateway()
	if err != nil {
		panic(err)
	}
	dstMac, err := getMacAddr(gwIp)
	if err != nil {
		panic(err)
	}

	fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(hToNs(syscall.ETH_P_ALL)))
	addr := syscall.SockaddrLinklayer{
		Ifindex: ifc.Index,
		Halen:   6, // Ethernet address length is 6 bytes
		Addr: [8]uint8{
			dstMac[0],
			dstMac[1],
			dstMac[2],
			dstMac[3],
			dstMac[4],
			dstMac[5],
		},
	}
	ethHeader := []byte{
		dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5],
		srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5],
		0x08, 0x00, // ipv4
	}

	return &Sender{
		EthHeader: ethHeader,
		Addr:      addr,
		Fd:        fd,
	}
}

func getDefGateway() (net.IP, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1]), nil
		}
	}
	return nil, errors.New("default gateway not found")
}

func getMacAddr(ip net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("ip", "neigh", "show", ip.String()).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if net.ParseIP(f).Equal(ip) && i+4 < len(fields) {
			return net.ParseMAC(fields[i+4])
		}
	}
	return nil, errors.New("MAC address not found")
}

func hToNs(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (l2 *Sender) Send(payload []byte) {
	p := append(l2.EthHeader, payload...)

	//err := syscall.Sendto(l2.Fd, p, 0, &l2.Addr)
	err := syscall.Sendmsg(l2.Fd, p, []byte{}, &l2.Addr, 0)
	if err != nil {
		panic(err)
	}
}

func getSender(seq uint16) (*Sender, net.IP) {
	if seq%2 == 0 {
		return senderA, srcAIp
	} else {
		return senderB, srcBIp
	}
}

func sendPacket(sender *Sender, payload []byte, seq uint16, probe *Probe) {
	sender.Send(payload)
	createProbePoint(probe, seq, time.Now().UnixNano())
	//log.Printf("Request: target=%s seq=%d\n", target, seq)
}

func (pm B2B) sendPackets(payloads [][]byte, probe *Probe) {
	for seq := uint16(0); seq < pm.requestCount; seq++ {
		time.Sleep(pm.requestInterval)
		sender, _ := getSender(seq)
		sendPacket(sender, payloads[seq], seq, probe)
	}
}

// Receive
func setupReceiver(iface Iface) {
	defer recvWg.Done()
	handle, err := pcapgo.NewEthernetHandle(iface.Name)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(err)
	}

	protoFilter := proto.Id
	if proto.Filter != "" {
		protoFilter += " and " + proto.Filter
	}
	bpfFilter := fmt.Sprintf("ip and %s and dst host %s", protoFilter, iface.Ip)
	bpfInstr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, ifc.MTU, bpfFilter)
	if err != nil {
		panic(err)
	}

	bpfRaw := bpfutils.ToBpfRawInstructions(bpfInstr)
	if bpfErr := handle.SetBPF(bpfRaw); bpfErr != nil {
		panic(bpfErr)
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case packet := <-packetSource:
			go addToRecvChan(&ReplyInfo{
				Packet: packet,
				Time:   time.Now().UnixNano(),
			})
		case <-stopReceiving:
			return
		}
	}
}

func (pm SEQ) receivePacket(recvCh chan *ReplyInfo, expSrc string, expDst string, expSeq uint16, probe *Probe) bool {
	timeout := time.After(config.MaxRTT)
	for {
		select {
		case replyInfo := <-recvCh:
			return pm.processPacket(replyInfo, expSrc, expDst, expSeq, probe)
		case <-timeout:
			return false
		}
	}
}

func (pm B2B) receivePackets(recvCh chan *ReplyInfo, expSrc string, probe *Probe) (bool, uint16) {
	var recvCounter uint16
	repliesFound := make(chan struct{})
	timeout := time.After(config.MaxRTT)
	for {
		select {
		case replyInfo := <-recvCh:
			pm.processPacket(recvCounter, repliesFound, replyInfo, expSrc, probe)
		case <-repliesFound:
			return true, recvCounter
		case <-timeout:
			return false, recvCounter
		}
	}
}

// Receive Channel
func createRecvChan(target string) chan *ReplyInfo {
	ch := make(chan *ReplyInfo)
	recvChans.Store(target, ch)
	return ch
}

func deleteRecvChan(target string) {
	recvChans.Delete(target)
}

func getRecvChan(target string) (chan *ReplyInfo, bool) {
	ch, ok := recvChans.Load(target)
	if !ok {
		return nil, false
	}
	return ch.(chan *ReplyInfo), true
}

func addToRecvChan(replyInfo *ReplyInfo) {
	if ipLayer := replyInfo.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ch, ok := getRecvChan(ip.SrcIP.String())
		if ok {
			ch <- replyInfo
		}
	}
}

// Process
func (pm SEQ) processPacket(replyInfo *ReplyInfo, expSrc string, expDst string, expSeq uint16, probe *Probe) bool {
	ok, src, dst, ipId := checkIPLayer(replyInfo.Packet)
	if !ok {
		log.Println("IPv4 layer invalid")
		return false
	}

	if src != expSrc {
		log.Println("Src is not expected")
		return false
	}

	if dst != expDst {
		// Commented because this happens too often due to double replies
		//log.Printf("[%s] Dst is not expected (dst=%s exp_dst=%s)", src, dst, expDst)
		return false
	}

	ok, seq := proto.CheckLayer(replyInfo.Packet, pm.requestCount)
	if !ok {
		log.Println("Protocol layer invalid")
		return false
	}

	if seq != expSeq {
		// Commented because this happens too often due to double replies
		//log.Printf("[%s] Seq is not expected (seq=%d exp_seq=%d)", src, seq, expSeq)
		return false
	}

	pp, ok := probe.Data[seq]
	if !ok {
		log.Println("No entry for probe")
		return false
	}

	if pp.Check {
		log.Println("Already received reply")
		return false
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt >= config.MaxRTT {
		log.Printf("RTT too high (rtt=%v, src=%s)", rtt, src)
		return false
	}

	pp.ReceivedTime = replyInfo.Time
	pp.IpId = ipId
	pp.Check = true
	//log.Printf("Reply: src=%s seq=%d rtt=%v ip_id=%d\n", src, seq, rtt, ipId)
	return true
}

func (pm B2B) processPacket(recvCounter uint16, repliesFound chan struct{}, replyInfo *ReplyInfo, expSrc string, probe *Probe) {
	ok, src, _, ipId := checkIPLayer(replyInfo.Packet)
	if !ok {
		log.Println("IPv4 layer invalid")
		return
	}

	if src != expSrc {
		log.Println("Src is not expected")
		return
	}

	ok, seq := proto.CheckLayer(replyInfo.Packet, pm.requestCount)
	if !ok {
		log.Println("Protocol layer invalid")
		return
	}

	pp, ok := probe.Data[seq]
	if !ok {
		log.Println("No entry for probe")
		return
	}

	if pp.Check {
		log.Println("Already received reply")
		return
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt >= config.MaxRTT {
		log.Printf("RTT too high (rtt=%v, src=%s)", rtt, src)
		return
	}

	pp.ReceivedTime = replyInfo.Time
	pp.IpId = ipId
	pp.Check = true
	//log.Printf("Reply: src=%s seq=%d rtt=%v ipid=%d\n", src, seq, rtt, ipId)
	recvCounter++
	if recvCounter == pm.requestCount {
		close(repliesFound)
	}
}

// Output
func (pv ProbingVars) createOutputDir(basePath string) string {
	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	outputDir := filepath.Join("results", pv.dirName, basePath, timeStamp) // TODO Use constants for "results" or "targets"
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		panic(err)
	}
	return outputDir
}

func saveProbes(outputDir string) {
	defer saveWg.Done()

	filePath := filepath.Join(outputDir, "probing.csv")
	var file *os.File
	var err error

	// Create the file and open it in write mode (not append)
	file, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	// Create a CSV writer
	headerWriter := csv.NewWriter(file)

	// Write CSV header
	err = headerWriter.Write([]string{config.IpColName, config.IpIdSeqColName, config.SendTsColName, config.RecvTsColName, config.CheckSeqColName})
	if err != nil {
		panic(err)
	}
	headerWriter.Flush()

	// Close the file after writing header
	err = file.Close()
	if err != nil {
		return
	}

	// Reopen the file in append mode to write probe data
	file, err = os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error reopening file in append mode: %v", err)
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	dataWriter := csv.NewWriter(file)
	defer dataWriter.Flush()

	// Read from channel and write each probe to the CSV file
	for probe := range probeSaveChan {
		var ipData []string
		ipData = append(ipData, probe.IPAddr)

		// Collect probe point data
		var ipIds []string
		var sentTimes []string
		var receivedTimes []string
		var checks []string

		for _, pp := range probe.Data {
			ipIds = append(ipIds, strconv.Itoa(int(pp.IpId)))
			sentTimes = append(sentTimes, strconv.FormatInt(pp.SentTime, 10))
			receivedTimes = append(receivedTimes, strconv.FormatInt(pp.ReceivedTime, 10))
			checks = append(checks, formatBool(pp.Check))
		}

		// Format record for CSV
		record := append(ipData, fmt.Sprintf("(%s)", joinWithComma(ipIds)))
		record = append(record, fmt.Sprintf("(%s)", joinWithComma(sentTimes)))
		record = append(record, fmt.Sprintf("(%s)", joinWithComma(receivedTimes)))
		record = append(record, fmt.Sprintf("(%s)", joinWithComma(checks)))

		// Write the record to the CSV file
		if writeErr := dataWriter.Write(record); writeErr != nil {
			log.Printf("Error writing record to CSV: %v", writeErr)
		}
	}
}

func joinWithComma(slice []string) string {
	return strings.Join(slice, ",")
}

func formatBool(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// Setup
func loadConfig() {
	err := cleanenv.ReadConfig("config.yaml", &config)
	if err != nil {
		panic(err)
	}

	srcAIp = net.ParseIP(config.IfaceA.Ip).To4()
	srcBIp = net.ParseIP(config.IfaceB.Ip).To4()
	targetSendMbps = parseBandwidth(config.SendBandwidth)
}

func parseBandwidth(value string) int {
	multipliers := map[string]int{
		"K": 1_000,
		"M": 1_000_000,
		"G": 1_000_000_000,
	}

	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) < 2 {
		panic(fmt.Sprintf("invalid input: %s", value))
	}

	unit := value[len(value)-1:]
	numPart := value[:len(value)-1]
	val, err := strconv.Atoi(numPart)
	if err != nil {
		panic(err)
	}

	mult, ok := multipliers[unit]
	if !ok {
		panic(fmt.Sprintf("unknown unit: %s", unit))
	}

	return val * mult
}

func getSortedDirectories(dir string) ([]string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var dirList []string
	for _, file := range files {
		if file.IsDir() {
			dirList = append(dirList, file.Name())
		}
	}

	sort.Slice(dirList, func(i, j int) bool {
		return dirList[i] < dirList[j]
	})

	return dirList, nil
}

func getBasePath() string {
	switch config.Protocol {
	case "icmp":
		return filepath.Join(config.Protocol)
	case "tcp":
		return filepath.Join(config.Protocol, strconv.Itoa(int(config.TcpDstPort)))
	case "udp":
		return filepath.Join(config.Protocol, strconv.Itoa(int(config.UdpDstPort)))
	default:
		panic("unknown protocol: " + config.Protocol)
	}
}

func loadTargets(targetsBasePath string, basePath string, outputDir string) string {
	// TODO zstd -d (...)/targets.csv.zst

	if targetsBasePath == "latest" {
		dir := filepath.Join("targets", basePath)
		allDirs, err := getSortedDirectories(dir)
		if err != nil {
			panic("failed to read directories: " + err.Error())
		}
		if len(allDirs) == 0 {
			panic("no directories found in: " + dir)
		}
		latestDir := allDirs[len(allDirs)-1]

		targetsBasePath = filepath.Join(basePath, latestDir)
	}

	sourceTargetsPath := filepath.Join(targetsBasePath, "targets.csv") // TODO Make targets.csv as constant
	absSourceTargetsPath, absErr := filepath.Abs(sourceTargetsPath)
	if absErr != nil {
		panic(absErr)
	}
	linkTargetsPath := filepath.Join(outputDir, "targets.csv")
	linkErr := os.Symlink(absSourceTargetsPath, linkTargetsPath)
	if linkErr != nil {
		panic(linkErr)
	}

	return linkTargetsPath
}

func loadProtocol(protocol string) *Protocol {
	switch protocol {
	case "icmp":
		return ICMP // TODO Make "icmp", "tcp", "udp" constants
	case "tcp":
		return TCP
	case "udp":
		return UDP
	default:
		panic("Unknown protocol")
	}
}

func loadProbingMode(mode string) {
	if mode == "b2b" {
		pm = B2B{
			ProbingVars: ProbingVars{
				requestCount: config.B2BReqCount,
				retryCount:   config.B2BRetryCount,
				dirName:      "b2b",
			},
			requestInterval: config.B2BReqInterval,
		}
	} else if mode == "seq" {
		pm = SEQ{
			ProbingVars: ProbingVars{
				requestCount: config.SEQReqCount,
				retryCount:   config.SEQRetryCount,
				dirName:      "seq",
			},
		}
	} else {
		panic(fmt.Sprintf("Unsupported mode: %s", mode))
	}
}

// Build
func (pv ProbingVars) buildPackets(rawIPLayers []layers.IPv4, dstIP net.IP) ([][]byte, int) {
	ipLayersCopy := make([]layers.IPv4, len(rawIPLayers))
	copy(ipLayersCopy, rawIPLayers)

	for i := range ipLayersCopy {
		ipLayersCopy[i].DstIP = dstIP
	}
	return proto.CreateLayers(ipLayersCopy, pv.requestCount)
}

func buildLayers(payloadLayers ...gopacket.SerializableLayer) []byte {
	pBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pBuf, opts, payloadLayers...)
	if err != nil {
		panic(err)
	}
	return pBuf.Bytes()
}

// IP
func (pv ProbingVars) createRawIPLayers() []layers.IPv4 {
	ipLayers := make([]layers.IPv4, pv.requestCount)

	for seq := uint16(0); seq < pv.requestCount; seq++ {
		_, srcIP := getSender(seq)

		id := config.DefaultSendIpIds[int(seq)%len(config.DefaultSendIpIds)]
		if config.DetectReflectedIpIds {
			id = config.ReflectionSendIpIds[int(seq)%len(config.ReflectionSendIpIds)]
		}

		ipLayer := layers.IPv4{
			Version:  ipv4.Version,
			TTL:      64,
			Id:       id,
			Flags:    0,
			Protocol: proto.IpLayer,
			SrcIP:    srcIP,
		}

		ipLayers[seq] = ipLayer
	}
	return ipLayers
}

func checkIPLayer(packet gopacket.Packet) (bool, string, string, uint16) {
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		log.Println("IPv4 layer invalid")
		return false, "", "", 0
	}

	if !ip.DstIP.Equal(srcAIp) && !ip.DstIP.Equal(srcBIp) {
		log.Println("DstIP not match")
		return false, "", "", 0
	}

	return true, ip.SrcIP.String(), ip.DstIP.String(), ip.Id
}

// ICMP
func createICMPLayers(ipLayers []layers.IPv4, requestCount uint16) ([][]byte, int) {
	pList := make([][]byte, requestCount)
	var byteSize int

	for seq := uint16(0); seq < requestCount; seq++ {
		ipLayer := ipLayers[seq]
		ipLayerCopy := ipLayer

		pLayer := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Seq:      seq,
		}

		packet := buildLayers(&ipLayerCopy, &pLayer)
		pList[seq] = packet
		byteSize += len(packet)
	}
	return pList, byteSize
}

func checkICMPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
	if icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		if icmp.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			if icmp.Seq < requestCount {
				return true, icmp.Seq
			}
		}
	}
	return false, 0
}

// TCP
func createTCPLayers(ipLayers []layers.IPv4, requestCount uint16) ([][]byte, int) {
	pList := make([][]byte, requestCount)
	var byteSize int

	for seq := uint32(0); seq < uint32(requestCount); seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.TCP{
			SrcPort: layers.TCPPort(seq + uint32(config.TcpSrcPortOffset)),
			DstPort: config.TcpDstPort,
			Seq:     seq,
			SYN:     strings.Contains(config.TcpReqFlags, "S"),
			ACK:     strings.Contains(config.TcpReqFlags, "A"),
			RST:     strings.Contains(config.TcpReqFlags, "R"),
		}
		err := pLayer.SetNetworkLayerForChecksum(&ipLayer)
		if err != nil {
			panic(err)
		}

		packet := buildLayers(&ipLayer, &pLayer)
		pList[seq] = packet
		byteSize += len(packet)
	}
	return pList, byteSize
}

func checkTCPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		if uint16(tcp.Ack-1) < requestCount {
			return true, uint16(tcp.Ack - 1)
		} else {
			log.Println("TCP Ack is invalid")
		}
	} else {
		log.Println("TCP layer not found")
	}
	return false, 0
}

// UDP
func createUDPLayers(ipLayers []layers.IPv4, requestCount uint16) ([][]byte, int) {
	pList := make([][]byte, requestCount)
	var byteSize int

	for seq := uint16(0); seq < requestCount; seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.UDP{
			SrcPort: layers.UDPPort(seq + config.UdpSrcPortOffset),
			DstPort: config.UdpDstPort,
		}
		err := pLayer.SetNetworkLayerForChecksum(&ipLayer)
		if err != nil {
			panic(err)
		}

		dnsLayer := layers.DNS{
			ID:      seq,
			OpCode:  layers.DNSOpCodeQuery,
			RD:      false,
			QDCount: 1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte("example.com"),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
		}

		packet := buildLayers(&ipLayer, &pLayer, &dnsLayer)
		pList[seq] = packet
		byteSize += len(packet)
	}
	return pList, byteSize
}

func checkUDPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
	if _, udpOk := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); udpOk {
		if dns, dnsOk := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dnsOk {
			if _, icmpOk := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); !icmpOk {
				if dns.QR {
					if dns.ID < requestCount {
						return true, dns.ID
					} else {
						log.Println("DNS ID is invalid")
					}
				} else {
					log.Println("DNS QR is invalid")
				}
			} else {
				log.Println("ICMP Layer found")
			}
		} else {
			log.Println("DNS Layer not found")
		}
	} else {
		log.Println("UDP Layer not found")
	}
	return false, 0
}

// Record Traffic
func startRecording(outputDir string) {
	interfaces := []Iface{config.IfaceA, config.IfaceB}
	for _, iface := range interfaces {
		outputFile := filepath.Join(outputDir, iface.Name+".pcap")
		cmd := exec.Command("tcpdump", "-i", iface.Name, "-w", outputFile, "-U", "-p")
		err := cmd.Start()
		if err != nil {
			panic(err)
		}
		recordingProcesses = append(recordingProcesses, cmd)
	}
}

func stopRecording() {
	for _, cmd := range recordingProcesses {
		if err := cmd.Process.Kill(); err != nil {
			panic(err)
		}
	}
	recordingProcesses = nil
}

// Tools
func setRSTDrop(enable bool) bool {
	checkCmd := exec.Command("sudo", "iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
	err := checkCmd.Run()
	ruleExists := err == nil

	if enable && !ruleExists {
		cmd := exec.Command("sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		if err := cmd.Run(); err != nil {
			panic(err)
		}
		return true
	} else if !enable && ruleExists {
		cmd := exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		if err := cmd.Run(); err != nil {
			panic(err)
		}
		return true
	}
	return false
}

// Stats
func logStatistics() {
	tickCount := 0
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	var lastWorkers int
	var warmupStartTime time.Time
	var warmupProbes int
	var warmedUp bool

	for range ticker.C {
		statsMu.Lock()

		tickCount++

		// Fortschritt
		probedPercentage := float64(totalProbes) / float64(totalTargetCount) * 100
		validPercentage := 0.0
		if totalProbes > 0 {
			validPercentage = float64(validProbes) / float64(totalProbes) * 100
		}

		// Bandbreite berechnen
		sentBit := deltaByteSize * 8
		sentMbps := float64(sentBit) / (1_000_000.0 * duration.Seconds())
		deltaByteSize = 0

		// Dynamische Anpassung
		diff := sentMbps - float64(targetSendMbps)
		factor := diff / float64(targetSendMbps)

		lastWorkers = currentWorkers
		if factor < -0.1 {
			adjust := int(math.Round(float64(currentWorkers) * -factor))
			addWorkers(adjust)
		} else if factor > 0.1 {
			adjust := int(math.Round(float64(currentWorkers) * factor))
			removeWorkers(adjust)
		}

		// Warmup
		absDeltaWorkerDiff := math.Abs(float64(currentWorkers-lastWorkers)) / float64(currentWorkers)
		if !warmedUp && (absDeltaWorkerDiff <= 0.1 || tickCount > 20) {
			warmedUp = true

			// Reset baseline
			warmupStartTime = time.Now()
			warmupProbes = totalProbes
		}

		// Geschätzte Restzeit nach Warmup
		timeLeft := "Warming up..."
		if warmedUp {
			elapsedSinceWarmedUp := time.Since(warmupStartTime)
			probesSinceWarmedUp := totalProbes - warmupProbes
			if probesSinceWarmedUp > 0 {
				remainingTime := time.Duration(float64(elapsedSinceWarmedUp) / float64(probesSinceWarmedUp) * float64(totalTargetCount-totalProbes))

				days := int(remainingTime.Hours()) / 24
				hours := int(remainingTime.Hours()) % 24
				minutes := int(remainingTime.Minutes()) % 60
				seconds := int(remainingTime.Seconds()) % 60

				timeLeft = ""
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
			}
		}

		fmt.Printf("estimated_time_left=[%s] probed_ip_addresses=[%d, %.2f%%] valid_probes=[%d, %.2f%%] used_bandwidth=[%.2f Mbps] workers=[%d]\n",
			timeLeft, totalProbes, probedPercentage, validProbes, validPercentage, sentMbps, currentWorkers)

		statsMu.Unlock()
	}
}

func updateStats(isValidProbe bool, probeByteSize int) {
	statsMu.Lock()
	defer statsMu.Unlock()
	totalProbes++
	if isValidProbe {
		validProbes++
	}
	deltaByteSize += probeByteSize
}
