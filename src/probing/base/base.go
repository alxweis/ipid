package base

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/breml/bpfutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/ipv4"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

import _ "net/http/pprof"

type ProbingMode interface {
	probingVars() *ProbingVars
	probeTarget(workerId uint16, recvCh chan *ReplyInfo, target net.IP)
}

type ProbingVars struct {
	retryCount   uint16
	requestCount uint16
	dirName      string
}

type B2B struct {
	*ProbingVars
	requestInterval time.Duration
}

func (pm *B2B) probingVars() *ProbingVars { return pm.ProbingVars }

type SEQ struct {
	*ProbingVars
}

func (pm *SEQ) probingVars() *ProbingVars { return pm.ProbingVars }

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
	DefaultSendIpIds     []uint16       `yaml:"default_send_ip_ids"`
	DetectReflectedIpIds bool           `yaml:"detect_reflected_ip_ids"`
	ReflectionSendIpIds  []uint16       `yaml:"reflection_send_ip_ids"`
	IpColName            string         `yaml:"ip_col_name"`
	IpIdSeqColName       string         `yaml:"ip_id_seq_col_name"`
	SentTsColName        string         `yaml:"sent_ts_seq_col_name"`
	RecvTsColName        string         `yaml:"received_ts_seq_col_name"`
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
	Target net.IP
	Data   map[uint16]*ProbePoint
}

type ReplyInfo struct {
	Packet gopacket.Packet
	Time   int64
	Seq    uint16
}

type Protocol struct {
	Id           string
	Filter       string
	IpLayer      layers.IPProtocol
	CreateLayers func(ipLayers []layers.IPv4, workerId uint16, requestCount uint16) [][]byte
	GetLayerData func(replyInfo *ReplyInfo) (uint16, uint16, bool)
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
		GetLayerData: getDataICMPLayer,
	}
	TCP = &Protocol{
		Id:           "tcp",
		Filter:       "",
		IpLayer:      layers.IPProtocolTCP,
		CreateLayers: createTCPLayers,
		GetLayerData: getDataTCPLayer,
	}
	UDP = &Protocol{
		Id:           "udp",
		Filter:       "",
		IpLayer:      layers.IPProtocolUDP,
		CreateLayers: createUDPLayers,
		GetLayerData: getDataUDPLayer,
	}
)

const (
	workers = 4096
)

var (
	pm                   ProbingMode
	config               Config
	srcAIp               net.IP
	srcBIp               net.IP
	workerWg             sync.WaitGroup
	recvWg               sync.WaitGroup
	saveWg               sync.WaitGroup
	stopReceiving        = make(chan struct{})
	probeSaveChan        = make(chan *Probe, workers*2)
	recvChans            [workers]chan *ReplyInfo
	targetCh             = make(chan net.IP, workers*2)
	opts                 = gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	recordingProcesses   []*exec.Cmd
	totalTargetCount     int64
	totalValidProbeCount int64
	totalProbeCount      int64
	totalSentByteCount   int64
	senderA              *Sender
	senderB              *Sender
	rawIPLayers          []layers.IPv4
	proto                *Protocol
	rstChanged           bool
	outputDir            string
	stopSignal           = make(chan struct{})
)

func Main(mode string) {
	setupSignalHandler()

	// Start pprof server
	go func() {
		err := http.ListenAndServe("localhost:6060", nil)
		if err != nil {
			return
		}
	}()

	// Utilize all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Load configuration
	loadConfig()

	// Load probing mode
	loadProbingMode(mode)

	basePath := getBasePath()
	createOutputDir(basePath)

	// Load targets file
	targetsFile := loadTargets(config.Targets, basePath)

	// Load protocol and raw IP layers
	loadProtocol(config.Protocol)
	createRawIPLayers()

	// Setup senders
	senderA = setupSender(config.IfaceA)
	senderB = setupSender(config.IfaceB)

	// Start saving probes
	saveWg.Add(1)
	go saveProbes()

	// Start recording if enabled
	if config.RecTraffic {
		startRecording()
	}

	// Block auto-send RST when using TCP
	//if proto.Id == "tcp" {
	//	rstChanged = setRSTDrop(true)
	//}

	// Start receivers
	recvWg.Add(2)
	go setupReceiver(config.IfaceA)
	go setupReceiver(config.IfaceB)

	// Count total targets
	countTotalTargets(targetsFile)

	// Open targetsFile
	f, err := os.Open(targetsFile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			panic(err)
		}
	}()

	zr, err := zstd.NewReader(f)
	if err != nil {
		panic(err)
	}
	defer zr.Close()

	scanner := bufio.NewScanner(zr)

	// Skip header line and find IP column index
	ipColIndex := -1
	if scanner.Scan() {
		header := strings.Split(scanner.Text(), ",")
		for i, col := range header {
			if strings.TrimSpace(col) == config.IpColName {
				ipColIndex = i
				break
			}
		}
	}

	// Start initial workers
	for i := uint16(0); i < workers; i++ {
		workerWg.Add(1)
		recvChans[i] = make(chan *ReplyInfo, pm.probingVars().requestCount)
		go worker(i)
	}

	// Start statistics goroutine
	go logStatistics()

	// Send targets to channel
	stopReadingTargetsFile := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 1 {
			continue
		}

		target := net.ParseIP(fields[ipColIndex]).To4()

		if target == nil {
			continue
		}

		select {
		case targetCh <- target: // Send target to channel
		case <-stopSignal:
			stopReadingTargetsFile = true
		}

		if stopReadingTargetsFile {
			break
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	cleanup()
}

func countTotalTargets(targetsFile string) {
	f, err := os.Open(targetsFile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			panic(err)
		}
	}()

	zr, err := zstd.NewReader(f)
	if err != nil {
		panic(err)
	}
	defer zr.Close()

	scanner := bufio.NewScanner(zr)

	if scanner.Scan() {
		// Skip header line
	}

	totalTargetCount = 0
	for scanner.Scan() {
		if scanner.Text() != "" {
			totalTargetCount++
		}
	}

	if err = scanner.Err(); err != nil {
		panic(err)
	}
}

func cleanup() {
	log.Println("Cleaning up workers...")
	close(targetCh)
	workerWg.Wait()

	log.Println("Cleaning up probe save channel...")
	close(probeSaveChan)
	saveWg.Wait()

	log.Println("Cleaning up receivers...")
	close(stopReceiving)
	recvWg.Wait()

	if config.RecTraffic {
		log.Println("Stopping record...")
		stopRecording()
	}

	//if rstChanged {
	//	log.Println("Unblock auto-send RST")
	//	setRSTDrop(false)
	//}

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
func createProbe(target net.IP) *Probe {
	atomic.AddInt64(&totalProbeCount, 1)
	return &Probe{
		Target: target,
		Data:   make(map[uint16]*ProbePoint),
	}
}

// Worker
func worker(ident uint16) {
	defer workerWg.Done()

	// Random delay before starting
	delay := time.Duration(rand.Intn(workers*2)) * time.Millisecond
	time.Sleep(delay)

	recvCh := recvChans[ident]
	for target := range targetCh {
		select {
		case <-stopSignal:
			return
		default:
			pm.probeTarget(ident, recvCh, target)
		}
	}
}

// Probing
func (pm *SEQ) probeTarget(workerId uint16, recvCh chan *ReplyInfo, target net.IP) {
	packets := buildPackets(target, workerId)

	probe := createProbe(target)
	recvCounter := uint16(0)
	retriesLeft := pm.retryCount
	sentByteCount := 0
	//startTime := time.Now()

	for {
		// Probe Target
		for seq := uint16(0); seq < pm.requestCount; seq++ {
			sender, senderIP := getSender(seq)
			sendPacket(sender, packets[seq], seq, probe, &sentByteCount)
			if pm.receivePacket(recvCh, target, senderIP, seq, probe) {
				recvCounter++
			} else {
				break // Stop probing if no reply found
			}
		}

		if recvCounter == pm.requestCount { // Successfully finished probing
			probeSaveChan <- probe
			atomic.AddInt64(&totalValidProbeCount, 1)
			break
		} else if retriesLeft > 0 { // Failed probing attempt, retrying
			retriesLeft--
			// Reset variables for next attempt
			recvCounter = 0
			probe.Data = make(map[uint16]*ProbePoint)
		} else { // All probing attempts failed
			//log.Printf("Probing failed for target %s", target)
			break
		}
	}

	atomic.AddInt64(&totalSentByteCount, int64(sentByteCount))

	//log.Printf("Finished probing target=[%s] received=[%d/%d] used_retries=[%d] sent_bytes=[%d] probing_duration=[%v]", target, recvCounter, pm.requestCount, pm.retryCount-retriesLeft, sentByteCount, time.Since(startTime))
}

func (pm *B2B) probeTarget(workerId uint16, recvCh chan *ReplyInfo, target net.IP) {
	packets := buildPackets(target, workerId)

	probe := createProbe(target)
	//recvCounter := uint16(0)
	retriesLeft := pm.retryCount
	sentByteCount := 0
	//startTime := time.Now()

	for {
		// Probe Target
		pm.sendPackets(packets, probe, &sentByteCount)
		foundAllReplies, _ := pm.receivePackets(recvCh, target, probe)
		//recvCounter = rc

		if foundAllReplies { // Successfully finished probing
			probeSaveChan <- probe
			atomic.AddInt64(&totalValidProbeCount, 1)
			break
		} else if retriesLeft > 0 { // Failed probing attempt, retrying
			retriesLeft--
			// Reset variables for next attempt
			probe.Data = make(map[uint16]*ProbePoint)
		} else { // All probing attempts failed
			break
		}
	}

	atomic.AddInt64(&totalSentByteCount, int64(sentByteCount))

	//log.Printf("Finished probing target=[%s] received=[%d/%d] used_retries=[%d] sent_bytes=[%d] probing_duration=[%v]", target, recvCounter, pm.requestCount, pm.retryCount-retriesLeft, sentByteCount, time.Since(startTime))
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

func (l2 *Sender) Send(packet []byte) {
	p := append(l2.EthHeader, packet...)

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

func sendPacket(sender *Sender, packet []byte, seq uint16, probe *Probe, sentByteCount *int) {
	sender.Send(packet)
	createProbePoint(probe, seq, time.Now().UnixMicro())
	*sentByteCount += len(packet)
	//log.Printf("Request: dst=[%s] seq=[%d]\n", probe.Target, seq)
}

func (pm *B2B) sendPackets(packets [][]byte, probe *Probe, sentByteCount *int) {
	for seq := uint16(0); seq < pm.requestCount; seq++ {
		if seq > 0 {
			time.Sleep(pm.requestInterval)
		}
		sender, _ := getSender(seq)
		sendPacket(sender, packets[seq], seq, probe, sentByteCount)
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
	bpfFilter := fmt.Sprintf("ip and (%s) and (dst host %s or dst host %s)", protoFilter, config.IfaceA.Ip, config.IfaceB.Ip)
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
				Time:   time.Now().UnixMicro(),
			})
		case <-stopReceiving:
			return
		}
	}
}

func (pm *SEQ) receivePacket(recvCh chan *ReplyInfo, expSrc net.IP, expDst net.IP, expSeq uint16, probe *Probe) bool {
	timeout := time.After(config.MaxRTT)
	for {
		select {
		case replyInfo := <-recvCh:
			switch pm.processPacket(replyInfo, expSrc, expDst, expSeq, probe) {
			case 0:
				return false // Invalid packet
			case 1:
				return true // Valid packet
			case 2:
				continue // Irrelevant packet, wait for next
			}
		case <-timeout:
			return false
		}
	}
}

func (pm *B2B) receivePackets(recvCh chan *ReplyInfo, expSrc net.IP, probe *Probe) (bool, uint16) {
	recvCounter := uint16(0)
	repliesFound := make(chan struct{})
	timeout := time.After(config.MaxRTT)
	for {
		select {
		case replyInfo := <-recvCh:
			pm.processPacket(&recvCounter, repliesFound, replyInfo, expSrc, probe)
		case <-repliesFound:
			return true, recvCounter
		case <-timeout:
			return false, recvCounter
		}
	}
}

// Receive Channel
func addToRecvChan(replyInfo *ReplyInfo) {
	seq, workerId, ok := proto.GetLayerData(replyInfo)

	if ok && seq < pm.probingVars().requestCount && workerId < workers {
		replyInfo.Seq = seq
		recvChans[workerId] <- replyInfo
	}
}

// Process
func (pm *SEQ) processPacket(replyInfo *ReplyInfo, expSrc net.IP, expDst net.IP, expSeq uint16, probe *Probe) int {
	ok, src, dst, ipId := checkIPLayer(replyInfo.Packet)
	if !ok {
		log.Println("IPv4 layer invalid")
		return 0
	}

	if !src.Equal(expSrc) {
		//log.Printf("[%s] Src is not expected (exp_src=[%s]) [If expSrc comes within timeout forget and continue else return false...]", src.String(), expSrc.String())
		return 2
	}

	if !dst.Equal(expDst) {
		// Commented because this happens too often due to double replies
		//log.Printf("[%s] Dst is not expected (dst=[%s] exp_dst=[%s])", src, dst, expDst)
		return 0
	}

	if replyInfo.Seq != expSeq {
		// Commented because this happens too often due to double replies
		log.Printf("[%s] Seq is not expected (seq=[%d] exp_seq=[%d])", src, replyInfo.Seq, expSeq)
		return 0
	}

	pp, ok := probe.Data[replyInfo.Seq]
	if !ok {
		log.Printf("[%s] No entry for probe", src)
		return 0
	}

	if pp.Check {
		log.Printf("[%s] Already received reply for request %d", src, replyInfo.Seq)
		return 0
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt > config.MaxRTT {
		log.Printf("[%s] RTT too high (rtt=[%v])", src, rtt)
		return 0
	}

	pp.ReceivedTime = replyInfo.Time
	pp.IpId = ipId
	pp.Check = true
	//log.Printf("Reply: src=[%s] seq=[%d] rtt=[%v] ip_id=[%d]\n", src, replyInfo.Seq, rtt, ipId)
	return 1
}

func (pm *B2B) processPacket(recvCounter *uint16, repliesFound chan struct{}, replyInfo *ReplyInfo, expSrc net.IP, probe *Probe) {
	ok, src, _, ipId := checkIPLayer(replyInfo.Packet)
	if !ok {
		log.Println("IPv4 layer invalid")
		return
	}

	if !src.Equal(expSrc) {
		//log.Printf("[%s] Src is not expected (exp_src=[%s]) [If expSrc comes within timeout forget and continue else return false...]", src.String(), expSrc.String())
		return
	}

	pp, ok := probe.Data[replyInfo.Seq]
	if !ok {
		log.Printf("[%s] No entry for probe", src)
		return
	}

	if pp.Check {
		//log.Printf("[%s] Already received reply for request %d", src, replyInfo.Seq)
		return
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt > config.MaxRTT {
		log.Printf("[%s] RTT too high (rtt=[%v])", src, rtt)
		return
	}

	pp.ReceivedTime = replyInfo.Time
	pp.IpId = ipId
	pp.Check = true
	//log.Printf("Reply: src=[%s] seq=[%d] rtt=[%v] ip_id=[%d]\n", src, replyInfo.Seq, rtt, ipId)
	*recvCounter++
	if *recvCounter == pm.requestCount {
		close(repliesFound)
	}
}

// Output
func createOutputDir(basePath string) {
	timeStamp := time.Now().Format("2006-01-02_15-04-05")
	outputDir = filepath.Join("results", pm.probingVars().dirName, basePath, timeStamp)
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		panic(err)
	}
}

func saveProbes() {
	defer saveWg.Done()

	filePath := filepath.Join(outputDir, "probing.csv.zst")

	// Create output file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer func() {
		err = file.Close()
		if err != nil {
			panic(err)
		}
	}()

	zw, err := zstd.NewWriter(file)
	if err != nil {
		panic(err)
	}
	defer func() {
		err = zw.Close()
		if err != nil {
			panic(err)
		}
	}()

	writer := bufio.NewWriter(zw)
	defer func() {
		err = writer.Flush()
		if err != nil {
			panic(err)
		}
	}()

	headerRecord := []string{config.IpColName, config.IpIdSeqColName, config.SentTsColName, config.RecvTsColName}
	_, err = writer.WriteString(joinWithComma(headerRecord) + "\n")
	if err != nil {
		panic(err)
	}

	length := int(pm.probingVars().requestCount)
	ipIds := make([]string, length)
	sentTimes := make([]string, length)
	receivedTimes := make([]string, length)

	// Read from channel and write each probe to the output file
	for probe := range probeSaveChan {
		if len(probe.Data) != length {
			panic("Probe Data has not correct length!")
		}

		for i, pp := range probe.Data {
			if !pp.Check {
				panic("Probe Point is not checked!")
			}
			ipIds[i] = strconv.Itoa(int(pp.IpId))
			sentTimes[i] = strconv.FormatInt(pp.SentTime, 10)
			receivedTimes[i] = strconv.FormatInt(pp.ReceivedTime, 10)
		}

		// Format record
		record := []string{
			probe.Target.String(),
			fmt.Sprintf("\"%s\"", joinWithComma(ipIds)),
			fmt.Sprintf("\"%s\"", joinWithComma(sentTimes)),
			fmt.Sprintf("\"%s\"", joinWithComma(receivedTimes)),
		}

		// Write the record to the output file
		_, err = writer.WriteString(joinWithComma(record) + "\n")
		if err != nil {
			panic(err)
		}
		if err != nil {
			panic(err)
		}
	}
}

func joinWithComma(arr []string) string {
	return strings.Join(arr, ",")
}

// Setup
func setupSignalHandler() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to handle the signal
	go func() {
		<-sigs
		log.Println("Received signal, exiting...")
		close(stopSignal)
	}()
}

func loadConfig() {
	err := cleanenv.ReadConfig("config.yaml", &config)
	if err != nil {
		panic(err)
	}

	srcAIp = net.ParseIP(config.IfaceA.Ip).To4()
	srcBIp = net.ParseIP(config.IfaceB.Ip).To4()
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

func loadTargets(targetsBasePath string, basePath string) string {
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

	sourceTargetsPath := filepath.Join(targetsBasePath, "targets_os.csv.zst")
	absSourceTargetsPath, absErr := filepath.Abs(sourceTargetsPath)
	if absErr != nil {
		panic(absErr)
	}
	linkTargetsPath := filepath.Join(outputDir, "targets_os.csv.zst")
	linkErr := os.Symlink(absSourceTargetsPath, linkTargetsPath)
	if linkErr != nil {
		panic(linkErr)
	}

	return linkTargetsPath
}

func loadProtocol(protocol string) {
	switch protocol {
	case "icmp":
		proto = ICMP
	case "tcp":
		proto = TCP
	case "udp":
		proto = UDP
	default:
		panic("Unknown protocol")
	}
}

func loadProbingMode(mode string) {
	if mode == "b2b" {
		pm = &B2B{
			ProbingVars: &ProbingVars{
				requestCount: config.B2BReqCount,
				retryCount:   config.B2BRetryCount,
				dirName:      "b2b",
			},
			requestInterval: config.B2BReqInterval,
		}
	} else if mode == "seq" {
		pm = &SEQ{
			ProbingVars: &ProbingVars{
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
func buildPackets(dstIP net.IP, workerId uint16) [][]byte {
	rawIpLayersCopy := make([]layers.IPv4, len(rawIPLayers))

	for i, rawIPLayer := range rawIPLayers {
		rawIpLayersCopy[i] = rawIPLayer
		rawIpLayersCopy[i].DstIP = dstIP
	}

	return proto.CreateLayers(rawIpLayersCopy, workerId, pm.probingVars().requestCount)
}

func buildLayers(payloadLayers ...gopacket.SerializableLayer) []byte {
	pBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pBuf, opts, payloadLayers...)
	if err != nil {
		panic(err)
	}
	return pBuf.Bytes()
}

// encode encodes the 4-bit number a and the 12-bit number b into a 16-bit number x.
func encode(a, b uint16) uint16 {
	return (a << 12) | (b & 0xFFF) // Shift a to the upper 4 bits, and set b to the lower 12 bits
}

// decode decodes the 16-bit number x back into the 4-bit number a and the 12-bit number b.
func decode(x uint16) (uint16, uint16) {
	a := x >> 12   // Extract the upper 4 bits of x for a
	b := x & 0xFFF // Extract the lower 12 bits of x for b
	return a, b
}

// IP
func createRawIPLayers() {
	ipLayers := make([]layers.IPv4, pm.probingVars().requestCount)

	for seq := uint16(0); seq < pm.probingVars().requestCount; seq++ {
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
	rawIPLayers = ipLayers
}

func checkIPLayer(packet gopacket.Packet) (bool, net.IP, net.IP, uint16) {
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		log.Println("IPv4 layer invalid")
		return false, nil, nil, 0
	}

	if !ip.DstIP.Equal(srcAIp) && !ip.DstIP.Equal(srcBIp) {
		log.Println("DstIP not match")
		return false, nil, nil, 0
	}

	return true, ip.SrcIP, ip.DstIP, ip.Id
}

// ICMP
func createICMPLayers(ipLayers []layers.IPv4, workerId uint16, requestCount uint16) [][]byte {
	pList := make([][]byte, requestCount)

	for seq := uint16(0); seq < requestCount; seq++ {
		ipLayer := ipLayers[seq]

		pLayer := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Seq:      encode(seq, workerId),
		}

		packet := buildLayers(&ipLayer, &pLayer)
		pList[seq] = packet
	}
	return pList
}

//func checkICMPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
//	if icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
//		if icmp.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
//			seq, _ := decode(icmp.Seq)
//			if seq < requestCount {
//				return true, seq
//			}
//		}
//	}
//	return false, 0
//}

func getDataICMPLayer(replyInfo *ReplyInfo) (uint16, uint16, bool) {
	if icmp, ok := replyInfo.Packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		if icmp.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			seq, workerId := decode(icmp.Seq)
			return seq, workerId, true
		}
	} else {
		log.Println("ICMP layer not found")
	}
	return 0, 0, false
}

// TCP
func createTCPLayers(ipLayers []layers.IPv4, workerId uint16, requestCount uint16) [][]byte {
	pList := make([][]byte, requestCount)

	for seq := uint16(0); seq < requestCount; seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.TCP{
			SrcPort: layers.TCPPort(seq + config.TcpSrcPortOffset),
			DstPort: config.TcpDstPort,
			Seq:     uint32(encode(seq, workerId)),
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
	}
	return pList
}

//func checkTCPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
//	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
//		seq, _ := decode(uint16(tcp.Ack - 1))
//		if seq < requestCount {
//			return true, seq
//		} else {
//			log.Println("TCP Ack is invalid")
//		}
//	} else {
//		log.Println("TCP layer not found")
//	}
//	return false, 0
//}

func getDataTCPLayer(replyInfo *ReplyInfo) (uint16, uint16, bool) {
	if tcp, ok := replyInfo.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		seq, workerId := decode(uint16(tcp.Ack - 1))
		return seq, workerId, true
	} else {
		log.Println("TCP layer not found")
	}
	return 0, 0, false
}

// UDP
func createUDPLayers(ipLayers []layers.IPv4, workerId uint16, requestCount uint16) [][]byte {
	pList := make([][]byte, requestCount)

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
			ID:      encode(seq, workerId),
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
	}
	return pList
}

//func checkUDPLayer(packet gopacket.Packet, requestCount uint16) (bool, uint16) {
//	if _, udpOk := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); udpOk {
//		if dns, dnsOk := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dnsOk {
//			if _, icmpOk := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); !icmpOk {
//				if dns.QR {
//					seq, _ := decode(dns.ID)
//					if seq < requestCount {
//						return true, seq
//					} else {
//						log.Println("DNS ID is invalid")
//					}
//				} else {
//					log.Println("DNS QR is invalid")
//				}
//			} else {
//				log.Println("ICMP Layer found")
//			}
//		} else {
//			log.Println("DNS Layer not found")
//		}
//	} else {
//		log.Println("UDP Layer not found")
//	}
//	return false, 0
//}

func getDataUDPLayer(replyInfo *ReplyInfo) (uint16, uint16, bool) {
	if _, udpOk := replyInfo.Packet.Layer(layers.LayerTypeUDP).(*layers.UDP); udpOk {
		if dns, dnsOk := replyInfo.Packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dnsOk {
			if _, icmpOk := replyInfo.Packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); !icmpOk {
				if dns.QR {
					seq, workerId := decode(dns.ID)
					return seq, workerId, true
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
	return 0, 0, false
}

// Record Traffic
func startRecording() {
	outputFile := filepath.Join(outputDir, "recording.pcap")
	cmd := exec.Command("tcpdump", "-i", "any", "-w", outputFile, "-U", "-p")
	err := cmd.Start()
	if err != nil {
		panic(err)
	}
	recordingProcesses = append(recordingProcesses, cmd)
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
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	startTime := time.Now()

	var (
		lastTotalProbeCount      int64
		lastTotalValidProbeCount int64
		lastTotalSentByteCount   int64
	)

	for range ticker.C {
		deltaTotalProbeCount := totalProbeCount - lastTotalProbeCount
		deltaTotalValidProbeCount := totalValidProbeCount - lastTotalValidProbeCount
		deltaTotalSentByteCount := totalSentByteCount - lastTotalSentByteCount

		// Percentages
		probeCountPercentage := float64(totalProbeCount) / float64(totalTargetCount) * 100
		validProbeCountPercentage := 0.0
		if totalProbeCount > 0 {
			validProbeCountPercentage = float64(totalValidProbeCount) / float64(totalProbeCount) * 100
		}

		// Sent bandwidth
		sentBit := deltaTotalSentByteCount * 8
		sentMbps := float64(sentBit) / (1_000_000.0 * duration.Seconds())

		// Estimated remaining time
		timeLeft := "Warming up..."
		elapsedTime := time.Since(startTime)
		if totalProbeCount > 0 {
			remainingTime := time.Duration(float64(elapsedTime) / float64(totalProbeCount) * float64(totalTargetCount-totalProbeCount))

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

		log.Printf("estimated_time_left=[%s] probed_ip_addresses=[%d, %.2f%%] valid_probes=[%d, %.2f%%] sent_mbps=[%.2f] workers=[%d]\n",
			timeLeft, deltaTotalProbeCount, probeCountPercentage, deltaTotalValidProbeCount, validProbeCountPercentage, sentMbps, workers)

		lastTotalProbeCount = totalProbeCount
		lastTotalValidProbeCount = totalValidProbeCount
		lastTotalSentByteCount = totalSentByteCount
	}
}
