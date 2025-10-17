package base

import (
	"bufio"
	"encoding/binary"
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
	"hash"
	"hash/fnv"
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
	probeTarget(recvCh chan *ReplyInfo, target net.IP)
}

type ProbingVars struct {
	retryCount   uint16
	requestCount uint16
	dirName      string
	maxRTT       time.Duration
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
	Targets                   string         `yaml:"targets"`
	Protocol                  string         `yaml:"protocol"`
	RecTraffic                bool           `yaml:"record_traffic"`
	TcpDstPort                layers.TCPPort `yaml:"tcp_dst_port"`
	TcpReqFlags               string         `yaml:"tcp_request_flags"`
	TcpSrcPortOffset          uint16         `yaml:"tcp_src_port_offset"`
	UdpDstPort                layers.UDPPort `yaml:"udp_dst_port"`
	UdpSrcPortOffset          uint16         `yaml:"udp_src_port_offset"`
	B2BReqCount               uint16         `yaml:"b2b_request_count"`
	B2BReqInterval            time.Duration  `yaml:"b2b_request_interval"`
	B2BRetryCount             uint16         `yaml:"b2b_retry_count"`
	SEQReqCount               uint16         `yaml:"seq_request_count"`
	SEQRetryCount             uint16         `yaml:"seq_retry_count"`
	MASSReqCount              uint16         `yaml:"mass_request_count"`
	MASSReqInterval           time.Duration  `yaml:"mass_request_interval"`
	MASSReplyPortionThreshold float64        `yaml:"mass_reply_portion_threshold"`
	IfaceA                    Iface          `yaml:"iface_a"`
	IfaceB                    Iface          `yaml:"iface_b"`
	MinRtt                    time.Duration  `yaml:"min_rtt"`
	DefaultSendIpIds          []uint16       `yaml:"default_send_ip_ids"`
	DetectReflectedIpIds      bool           `yaml:"detect_reflected_ip_ids"`
	ReflectionSendIpIds       []uint16       `yaml:"reflection_send_ip_ids"`
	IpColName                 string         `yaml:"ip_col_name"`
	IpIdSeqColName            string         `yaml:"ip_id_seq_col_name"`
	SentTsColName             string         `yaml:"sent_ts_seq_col_name"`
	RecvTsColName             string         `yaml:"received_ts_seq_col_name"`
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
}

type Protocol struct {
	Id          string
	Filter      string
	IpLayer     layers.IPProtocol
	CreateLayer func(seq uint16) []gopacket.SerializableLayer
	SetChecksum func(packet []byte)
	GetSeq      func(replyInfo *ReplyInfo) (uint16, bool)
}

type Sender struct {
	EthHeader []byte
	Fd        int
	Addr      syscall.SockaddrLinklayer
}

type Worker struct {
	targetCh chan net.IP
	recvCh   chan *ReplyInfo
}

var (
	ICMP = &Protocol{
		Id:          "icmp",
		Filter:      "icmp[icmptype] == icmp-echoreply",
		IpLayer:     layers.IPProtocolICMPv4,
		CreateLayer: createICMPLayer,
		SetChecksum: setICMPChecksum,
		GetSeq:      getICMPSeq,
	}
	TCP = &Protocol{
		Id:          "tcp",
		Filter:      "",
		IpLayer:     layers.IPProtocolTCP,
		CreateLayer: createTCPLayer,
		SetChecksum: setTCPChecksum,
		GetSeq:      getTCPSeq,
	}
	UDP = &Protocol{
		Id:          "udp",
		Filter:      "",
		IpLayer:     layers.IPProtocolUDP,
		CreateLayer: createUDPLayer,
		SetChecksum: setUDPChecksum,
		GetSeq:      getUDPSeq,
	}
)

const (
	workerCount        = 1 << 12
	workerTargetChSize = 1 << 6
	tcpSeqBase         = 2419684780
	allowRSTs          = false
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
	probeSaveChan        = make(chan *Probe, workerCount*2)
	workers              [workerCount]*Worker
	opts                 = gopacket.SerializeOptions{ComputeChecksums: false, FixLengths: true}
	recordingProcesses   []*exec.Cmd
	totalTargetCount     int64
	totalValidProbeCount int64
	totalProbeCount      int64
	totalSentByteCount   int64
	totalSentPacketCount int64
	senderA              *Sender
	senderB              *Sender
	prebuildPackets      [][]byte
	proto                *Protocol
	outputDir            string
	stopSignal           = make(chan struct{})
	isMassScan           bool
)

func Main(mode string, targetsType string) {
	setupSignalHandler()

	// Start pprof server
	go func() {
		err := http.ListenAndServe("localhost:6060", nil)
		if err != nil {
			panic(err)
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
	targetsFile := loadTargets(config.Targets, targetsType, basePath)

	// Load protocol and raw IP layers
	loadProtocol(config.Protocol)
	createPrebuildPackets()

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

	rstDropChanged := false
	if proto.Id == "tcp" {
		rstDropChanged, err = setRSTDrop(!allowRSTs)
		if err != nil {
			panic(err)
		}
		log.Println("RST drop enabled")
	}

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

	// Start receivers
	recvWg.Add(2)
	go setupReceiver(config.IfaceA)
	go setupReceiver(config.IfaceB)

	// Start workers
	for i := uint16(0); i < workerCount; i++ {
		workerWg.Add(1)
		workers[i] = &Worker{
			targetCh: make(chan net.IP, workerTargetChSize),
			recvCh:   make(chan *ReplyInfo, pm.probingVars().requestCount),
		}
		go startWorker(workers[i])
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

		workerId := hashIPAddrToWorkerId(target)

		select {
		case workers[workerId].targetCh <- target: // Send target to channel
		case <-stopSignal:
			stopReadingTargetsFile = true
		default:
			log.Printf("Target Channel %d is full, blocking %s...", workerId, target.String())
			workers[workerId].targetCh <- target
		}

		if stopReadingTargetsFile {
			break
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if proto.Id == "tcp" && rstDropChanged {
		_, err = setRSTDrop(allowRSTs)
		if err != nil {
			panic(err)
		}
		log.Println("RST drop disabled")
	}

	cleanup()
}

var hasherPool = sync.Pool{
	New: func() any { return fnv.New32a() },
}

func hashIPAddrToWorkerId(ipAddr net.IP) int {
	hasher := hasherPool.Get().(hash.Hash32)
	hasher.Reset()
	_, _ = hasher.Write(ipAddr)
	sum := hasher.Sum32()
	hasherPool.Put(hasher)
	return int(sum % workerCount)
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
	log.Println("Closing all worker target channels...")
	for _, w := range workers {
		close(w.targetCh)
	}

	log.Println("Waiting for workers to finish...")
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

// Start Worker
func startWorker(w *Worker) {
	defer workerWg.Done()

	// Random delay before starting
	delay := time.Duration(rand.Intn(workerCount*2)) * time.Millisecond
	time.Sleep(delay)

	for target := range w.targetCh {
		select {
		case <-stopSignal:
			return
		default:
			pm.probeTarget(w.recvCh, target)
		}
	}
}

// Probing
func (pm *SEQ) probeTarget(recvCh chan *ReplyInfo, target net.IP) {
	packets := buildPackets(target)

	probe := createProbe(target)
	recvCounter := uint16(0)
	retriesLeft := pm.retryCount
	sentByteCount := 0
	sentPacketCount := 0
	//startTime := time.Now()

	for {
		// Probe Target
		for seq := uint16(0); seq < pm.requestCount; seq++ {
			sender, senderIP := getSender(seq)
			sendPacket(sender, packets[seq], seq, probe, &sentByteCount, &sentPacketCount)
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
	atomic.AddInt64(&totalSentPacketCount, int64(sentPacketCount))

	//log.Printf("Finished probing target=[%s] received=[%d/%d] used_retries=[%d] sent_bytes=[%d] probing_duration=[%v]", target, recvCounter, pm.requestCount, pm.retryCount-retriesLeft, sentByteCount, time.Since(startTime))
}

func (pm *B2B) probeTarget(recvCh chan *ReplyInfo, target net.IP) {
	packets := buildPackets(target)

	probe := createProbe(target)
	//recvCounter := uint16(0)
	retriesLeft := pm.retryCount
	sentByteCount := 0
	sentPacketCount := 0
	//startTime := time.Now()

	for {
		// Probe Target
		pm.sendPackets(packets, probe, &sentByteCount, &sentPacketCount)
		foundAllReplies, rc := pm.receivePackets(recvCh, target, probe)
		//recvCounter = rc
		replyPortion := float64(rc) / float64(pm.requestCount)

		massScanCheck := isMassScan && (replyPortion >= config.MASSReplyPortionThreshold)

		//if replyPortion < config.MASSReplyPortionThreshold {
		//	log.Printf("%d/%d replies. Too few replies!", rc, pm.requestCount)
		//}

		if foundAllReplies || massScanCheck { // Successfully finished probing
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
	atomic.AddInt64(&totalSentPacketCount, int64(sentPacketCount))

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

	fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(hToNs(syscall.ETH_P_IP)))
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

func sendPacket(sender *Sender, packet []byte, seq uint16, probe *Probe, sentByteCount *int, sentPacketCount *int) {
	sender.Send(packet)
	createProbePoint(probe, seq, time.Now().UnixMicro())
	*sentByteCount += len(packet)
	*sentPacketCount += 1
	//log.Printf("Request: dst=[%s] seq=[%d]\n", probe.Target, seq)
}

func (pm *B2B) sendPackets(packets [][]byte, probe *Probe, sentByteCount *int, sentPacketCount *int) {
	for seq := uint16(0); seq < pm.requestCount; seq++ {
		if seq > 0 {
			time.Sleep(pm.requestInterval)
		}
		sender, _ := getSender(seq)
		sendPacket(sender, packets[seq], seq, probe, sentByteCount, sentPacketCount)
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
	bpfFilter := fmt.Sprintf("ether dst %s and ip and (%s) and dst host %s", ifc.HardwareAddr, protoFilter, iface.Ip)
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
	timeout := time.After(pm.probingVars().maxRTT)
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
	timeout := time.After(pm.probingVars().maxRTT)
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
	if ipLayer := replyInfo.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		workerId := hashIPAddrToWorkerId(ip.SrcIP)
		if workers[workerId] != nil {
			workers[workerId].recvCh <- replyInfo
		} else {
			log.Printf("Worker %d not initialized!", workerId)
		}
	}
}

// Process
func (pm *SEQ) processPacket(replyInfo *ReplyInfo, expSrc net.IP, expDst net.IP, expSeq uint16, probe *Probe) int {
	src, dst, ipId, ok := checkIPLayer(replyInfo)
	if !ok {
		log.Println("IPv4 layer invalid")
		return 0
	}

	if !src.Equal(expSrc) {
		//log.Printf("[%s] Src is not expected (exp_src=[%s]) [If expSrc comes within timeout forget and continue else return false...]", src.String(), expSrc.String())
		return 2
	}

	if !dst.Equal(expDst) {
		log.Printf("[%s] Dst is not expected (dst=[%s] exp_dst=[%s])", src, dst, expDst)
		return 0
	}

	seq, ok := proto.GetSeq(replyInfo)
	if !ok {
		log.Printf("[%s] Protocol layer invalid", src)
		return 0
	} else if !(seq < pm.probingVars().requestCount) {
		log.Printf("[%s] Seq is out of range (check seq=%d < %d failed)", src, seq, pm.probingVars().requestCount)
		return 0
	}

	if seq != expSeq {
		// Happens for ICMP/UDP due to double replies
		// Happens for TCP due to TCP retransmission
		log.Printf("[%s] Seq is not expected (seq=[%d] exp_seq=[%d])", src, seq, expSeq)
		return 0
	}

	// If TCP, send RST to abort handshake cleanly
	if proto.Id == "tcp" {
		sender, _ := getSender(seq)
		tcp, _ := replyInfo.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			rstPacket := buildRST(seq, dst, src, tcp.Ack)
			sender.Send(rstPacket)
			//log.Printf("Sent RST packet %.3f ms after SYN-ACK", float64(time.Now().UnixMicro()-replyInfo.Time)/1000)
		}
	}

	pp, ok := probe.Data[seq]
	if !ok {
		log.Printf("[%s] No entry for probe", src)
		return 0
	}

	if pp.Check {
		log.Printf("[%s] Already received reply for request %d", src, seq)
		return 0
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt > pm.probingVars().maxRTT {
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
	src, _, ipId, ok := checkIPLayer(replyInfo)
	if !ok {
		log.Println("IPv4 layer invalid")
		return
	}

	if !src.Equal(expSrc) {
		//log.Printf("[%s] Src is not expected (exp_src=[%s]) [If expSrc comes within timeout forget and continue else return false...]", src.String(), expSrc.String())
		return
	}

	seq, ok := proto.GetSeq(replyInfo)
	if !ok {
		//log.Printf("[%s] Protocol layer invalid", src)
		return
	} else if !(seq < pm.probingVars().requestCount) {
		log.Printf("[%s] Seq is out of range (check seq=%d < %d failed)", src, seq, pm.probingVars().requestCount)
		return
	}

	pp, ok := probe.Data[seq]
	if !ok {
		log.Printf("[%s] No entry for probe", src)
		return
	}

	if pp.Check {
		//log.Printf("[%s] Already received reply for request %d", src, replyInfo.Seq)
		return
	}

	rtt := time.Duration(replyInfo.Time - pp.SentTime)
	if rtt > pm.probingVars().maxRTT {
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

	// Read from channel and write each probe to the output file
	for probe := range probeSaveChan {
		if len(probe.Data) != length {
			panic("Probe Data has not correct length!")
		}

		var (
			ipIds         []string
			sentTimes     []string
			receivedTimes []string
		)

		keys := make([]int, 0, len(probe.Data))
		for k := range probe.Data {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)

		probePoints := make([]*ProbePoint, 0, len(keys))
		for _, k := range keys {
			probePoints = append(probePoints, probe.Data[uint16(k)])
		}

		for _, pp := range probePoints {
			if !pp.Check {
				if isMassScan {
					continue
				}
				panic("Probe Point is not checked!")
			}
			ipIds = append(ipIds, strconv.Itoa(int(pp.IpId)))
			sentTimes = append(sentTimes, strconv.FormatInt(pp.SentTime, 10))
			receivedTimes = append(receivedTimes, strconv.FormatInt(pp.ReceivedTime, 10))
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
	}
}

func joinWithComma(lst []string) string {
	return strings.Join(lst, ",")
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

func loadTargets(targetsBasePath string, targetsType string, basePath string) string {
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

	fileName := "targets.csv.zst"
	if targetsType == "os" {
		fileName = "targets_os.csv.zst"
	}
	sourceTargetsPath := filepath.Join(targetsBasePath, fileName)
	absSourceTargetsPath, absErr := filepath.Abs(sourceTargetsPath)
	if absErr != nil {
		panic(absErr)
	}
	linkTargetsPath := filepath.Join(outputDir, fileName)
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
				maxRTT:       time.Duration(config.B2BReqCount)*config.B2BReqInterval + config.MinRtt,
			},
			requestInterval: config.B2BReqInterval,
		}
	} else if mode == "seq" {
		pm = &SEQ{
			ProbingVars: &ProbingVars{
				requestCount: config.SEQReqCount,
				retryCount:   config.SEQRetryCount,
				dirName:      "seq",
				maxRTT:       config.MinRtt,
			},
		}
	} else if mode == "mass" {
		isMassScan = true
		pm = &B2B{
			ProbingVars: &ProbingVars{
				requestCount: config.MASSReqCount,
				retryCount:   0,
				dirName:      "mass",
				maxRTT:       time.Duration(config.MASSReqCount)*config.MASSReqInterval + config.MinRtt,
			},
			requestInterval: config.MASSReqInterval,
		}
	} else {
		panic(fmt.Sprintf("Unsupported mode: %s", mode))
	}
}

// Build
func createPrebuildPackets() {
	packetList := make([][]byte, pm.probingVars().requestCount)
	packetBuf := gopacket.NewSerializeBuffer()

	for seq := uint16(0); seq < pm.probingVars().requestCount; seq++ {
		_, srcIP := getSender(seq)

		id := config.DefaultSendIpIds[int(seq)%len(config.DefaultSendIpIds)]
		if config.DetectReflectedIpIds {
			id = config.ReflectionSendIpIds[int(seq)%len(config.ReflectionSendIpIds)]
		}

		ipLayer := &layers.IPv4{
			Version:  ipv4.Version,
			TTL:      64,
			Id:       id,
			Flags:    0,
			Protocol: proto.IpLayer,
			SrcIP:    srcIP,
			DstIP:    net.IPv4(0, 0, 0, 0),
		}

		protoLayer := proto.CreateLayer(seq)

		err := packetBuf.Clear()
		if err != nil {
			panic(err)
		}

		packetLayers := append([]gopacket.SerializableLayer{ipLayer}, protoLayer...)
		err = gopacket.SerializeLayers(packetBuf, opts, packetLayers...)
		if err != nil {
			panic(err)
		}

		packetList[seq] = append([]byte(nil), packetBuf.Bytes()...)
	}
	prebuildPackets = packetList
}

func buildPackets(dstIP net.IP) [][]byte {
	packetList := make([][]byte, pm.probingVars().requestCount)

	for seq := uint16(0); seq < pm.probingVars().requestCount; seq++ {
		packet := make([]byte, len(prebuildPackets[seq]))
		copy(packet, prebuildPackets[seq])

		// Set IP Destination
		copy(packet[16:20], dstIP)

		// Calculate IP checksum
		binary.BigEndian.PutUint16(packet[10:12], 0)
		ipChecksum := calculateChecksum(packet[0:20])
		binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

		// Calculate Protocol Checksum
		proto.SetChecksum(packet)

		packetList[seq] = packet
	}

	return packetList
}

// Standard Algorithm for computing Internet-Checksums referring RFC1071
func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Add all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		word := uint32(data[i])<<8 + uint32(data[i+1])
		sum += word
	}

	// If odd number of bytes, add the last byte
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

// IP
func checkIPLayer(replyInfo *ReplyInfo) (net.IP, net.IP, uint16, bool) {
	ip, ok := replyInfo.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		log.Println("IPv4 layer invalid")
		return nil, nil, 0, false
	}

	if !ip.DstIP.Equal(srcAIp) && !ip.DstIP.Equal(srcBIp) {
		log.Println("DstIP not match")
		return nil, nil, 0, false
	}

	return ip.SrcIP, ip.DstIP, ip.Id, true
}

// ICMP
func createICMPLayer(seq uint16) []gopacket.SerializableLayer {
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      seq,
	}

	return []gopacket.SerializableLayer{icmpLayer}
}

func setICMPChecksum(packet []byte) {
	// Set ICMP Checksum 0
	binary.BigEndian.PutUint16(packet[22:24], 0)

	icmpData := packet[20:]
	icmpChecksum := calculateChecksum(icmpData)
	binary.BigEndian.PutUint16(packet[22:24], icmpChecksum)
}

func getICMPSeq(replyInfo *ReplyInfo) (uint16, bool) {
	if icmp, ok := replyInfo.Packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		if icmp.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			return icmp.Seq, true
		}
	} else {
		log.Println("ICMP layer not found")
	}
	return 0, false
}

// TCP
func createTCPLayer(seq uint16) []gopacket.SerializableLayer {
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(seq + config.TcpSrcPortOffset),
		DstPort: config.TcpDstPort,
		Seq:     tcpSeqBase + uint32(seq),
		SYN:     strings.Contains(config.TcpReqFlags, "S"),
		ACK:     strings.Contains(config.TcpReqFlags, "A"),
		RST:     strings.Contains(config.TcpReqFlags, "R"),
		Window:  512,
	}

	return []gopacket.SerializableLayer{tcpLayer}
}

func setTCPChecksum(packet []byte) {
	// Set TCP Checksum 0
	binary.BigEndian.PutUint16(packet[36:38], 0)

	ipSrc := packet[12:16] // Source IP
	ipDst := packet[16:20] // Dest IP
	tcpData := packet[20:] // TCP Header + Data

	// Create Pseudo-Header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipSrc)
	copy(pseudoHeader[4:8], ipDst)
	pseudoHeader[8] = 0 // Zero
	pseudoHeader[9] = 6 // TCP Protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpData)))

	// Combine Pseudo-Header + TCP Data
	checksumData := append(pseudoHeader, tcpData...)
	checksum := calculateChecksum(checksumData)
	binary.BigEndian.PutUint16(packet[36:38], checksum)
}

func getTCPSeq(replyInfo *ReplyInfo) (uint16, bool) {
	if tcp, ok := replyInfo.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		seq := uint16(tcp.Ack - tcpSeqBase - 1)

		if tcp.SrcPort != config.TcpDstPort {
			log.Println("SrcPort is invalid")
			return 0, false
		}

		if tcp.DstPort != layers.TCPPort(seq+config.TcpSrcPortOffset) {
			log.Println("DstPort is invalid")
			return 0, false
		}

		if !((tcp.SYN && tcp.ACK) || (tcp.RST && tcp.ACK) || tcp.RST) {
			flags := ""
			if tcp.SYN {
				flags += "S"
			}
			if tcp.ACK {
				flags += "A"
			}
			if tcp.RST {
				flags += "R"
			}
			if tcp.FIN {
				flags += "F"
			}
			if tcp.PSH {
				flags += "P"
			}
			if tcp.URG {
				flags += "U"
			}

			log.Printf("Flags are invalid (%s). Should be SA, RA or R\n", flags)
			return 0, false
		}

		return seq, true
	} else {
		log.Println("TCP layer not found")
	}
	return 0, false
}

func setRSTDrop(enable bool) (changed bool, err error) {
	cmdCheck := exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
	errCheck := cmdCheck.Run()

	if enable {
		if errCheck == nil {
			return false, nil
		}
		cmdAdd := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err = cmdAdd.Run()
		return err == nil, err
	} else {
		if errCheck != nil {
			return false, nil
		}
		cmdDel := exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err = cmdDel.Run()
		return err == nil, err
	}
}

func buildRST(seq uint16, srcIP net.IP, dstIP net.IP, ack uint32) []byte {
	ipLayer := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      64,
		Id:       21305,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(seq + config.TcpSrcPortOffset),
		DstPort: config.TcpDstPort,
		Seq:     ack,
		RST:     true,
	}
	err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		panic(err)
	}

	buf := gopacket.NewSerializeBuffer()
	rstOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err = gopacket.SerializeLayers(buf, rstOpts, ipLayer, tcpLayer); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// UDP
func createUDPLayer(seq uint16) []gopacket.SerializableLayer {
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(seq + config.UdpSrcPortOffset),
		DstPort: config.UdpDstPort,
	}

	dnsLayer := &layers.DNS{
		ID:      seq,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      false,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(fmt.Sprintf("%d.example.com", seq)),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	return []gopacket.SerializableLayer{udpLayer, dnsLayer}
}

func setUDPChecksum(packet []byte) {
	// Set UDP Checksum 0
	binary.BigEndian.PutUint16(packet[26:28], 0)

	// Create Pseudo-Header
	ipSrc := packet[12:16]
	ipDst := packet[16:20]
	udpData := packet[20:]

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipSrc)
	copy(pseudoHeader[4:8], ipDst)
	pseudoHeader[8] = 0  // Zero
	pseudoHeader[9] = 17 // UDP Protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	// Combine Pseudo-Header + UDP Data
	checksumData := append(pseudoHeader, udpData...)
	checksum := calculateChecksum(checksumData)
	binary.BigEndian.PutUint16(packet[26:28], checksum)
}

func getUDPSeq(replyInfo *ReplyInfo) (uint16, bool) {
	if _, udpOk := replyInfo.Packet.Layer(layers.LayerTypeUDP).(*layers.UDP); udpOk {
		if dns, dnsOk := replyInfo.Packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dnsOk {
			if _, icmpOk := replyInfo.Packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); !icmpOk {
				if dns.QR {
					return dns.ID, true
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
	return 0, false
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

// Stats
func logStatistics() {
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	startTime := time.Now()

	var (
		lastTotalProbeCount      int64
		lastTotalValidProbeCount int64
		lastTotalSentByteCount   int64
		lastTotalSentPacketCount int64
	)

	for range ticker.C {
		deltaTotalProbeCount := totalProbeCount - lastTotalProbeCount
		deltaTotalValidProbeCount := totalValidProbeCount - lastTotalValidProbeCount
		deltaTotalSentByteCount := totalSentByteCount - lastTotalSentByteCount
		deltaTotalSentPacketCount := totalSentPacketCount - lastTotalSentPacketCount

		// Percentages
		probeCountPercentage := float64(totalProbeCount) / float64(totalTargetCount) * 100
		validProbeCountPercentage := 0.0
		if totalProbeCount > 0 {
			validProbeCountPercentage = float64(totalValidProbeCount) / float64(totalProbeCount) * 100
		}

		// Sent bandwidth
		sentBit := deltaTotalSentByteCount * 8
		sentMbps := float64(sentBit) / (1_000_000.0 * duration.Seconds())

		// Sent packet rate
		sentPps := float64(deltaTotalSentPacketCount) / duration.Seconds()

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

		log.Printf("estimated_time_left=[%s] probed_ip_addresses=[%d, %.2f%%] valid_probes=[%d, %d/%d=%.2f%%] sent_mbps=[%.2f] sent_pps=[%.0f] worker_count=[%d]\n",
			timeLeft, deltaTotalProbeCount, probeCountPercentage, deltaTotalValidProbeCount, totalValidProbeCount, totalProbeCount, validProbeCountPercentage, sentMbps, sentPps, workerCount)

		lastTotalProbeCount = totalProbeCount
		lastTotalValidProbeCount = totalValidProbeCount
		lastTotalSentByteCount = totalSentByteCount
		lastTotalSentPacketCount = totalSentPacketCount
	}
}
