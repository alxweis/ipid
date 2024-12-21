package probing_slow

import (
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
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Targets       string         `yaml:"targets"`
	Protocol      string         `yaml:"protocol"`
	TcpDstPort    layers.TCPPort `yaml:"tcpDstPort"`
	TcpSA         bool           `yaml:"tcpSA"`
	RecTraffic    bool           `yaml:"recTraffic"`
	ProbeCount    uint16         `yaml:"slowProbeCount"`
	IfaceA        Iface          `yaml:"IfaceA"`
	IfaceB        Iface          `yaml:"IfaceB"`
	MaxRTT        time.Duration  `yaml:"maxRTT"`
	MaxSendRate   int            `yaml:"maxSendRate"`
	TcpSrcPortOff uint32         `yaml:"tcpSrcPortOff"`
	UdpSrcPortOff uint16         `yaml:"udpSrcPortOff"`
	DefaultIpId   uint16         `yaml:"defaultIpId"`
	DetectMirror  bool           `yaml:"detectMirror"`
	MirrorIpIds   []uint16       `yaml:"mirrorIpIds"`
}

type Iface struct {
	Name string `yaml:"name"`
	Ip   string `yaml:"ip"`
}

type Probe struct {
	IsValid      bool   `json:"is_valid"`
	SentTime     int64  `json:"sent_time"`
	ReceivedTime int64  `json:"received_time"`
	IpId         uint16 `json:"ip_id"`
}

type ReplyInfo struct {
	Packet gopacket.Packet
	Time   int64
}

type Protocol struct {
	Id           string
	Filter       string
	IpLayer      layers.IPProtocol
	CreateLayers func(ipLayers []layers.IPv4) [][]byte
	CheckLayer   func(packet gopacket.Packet) (bool, uint16)
}

type Sender struct {
	EthHeader []byte
	Fd        int
	Addr      syscall.SockaddrLinklayer
}

var (
	ICMP = Protocol{
		Id:           "icmp",
		Filter:       "icmp[icmptype] == icmp-echoreply",
		IpLayer:      layers.IPProtocolICMPv4,
		CreateLayers: createICMPLayers,
		CheckLayer:   checkICMPLayer,
	}
	TCP = Protocol{
		Id:           "tcp",
		Filter:       "",
		IpLayer:      layers.IPProtocolTCP,
		CreateLayers: createTCPLayers,
		CheckLayer:   checkTCPLayer,
	}
	UDP = Protocol{
		Id:           "udp",
		Filter:       "",
		IpLayer:      layers.IPProtocolUDP,
		CreateLayers: createUDPLayers,
		CheckLayer:   checkUDPLayer,
	}
)

var (
	config        Config
	srcAIp        net.IP
	srcBIp        net.IP
	probingWg     sync.WaitGroup
	recvWg        sync.WaitGroup
	stopReceiving = make(chan struct{})
	results       sync.Map
	recvChans     sync.Map
	opts          = gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	targetsToOs   = make(map[string]string)
)

var (
	recordingProcesses []*exec.Cmd
)

func Main() {
	loadConfig()

	targets := loadTargets(config.Targets)

	proto := loadProtocol(config.Protocol)
	rawIPLayers := createRawIPLayers(proto)

	senderA := setupSender(config.IfaceA)
	senderB := setupSender(config.IfaceB)

	outputDir, msmId := createOutputDir()
	outputFile := createOutputFile(outputDir)

	if config.RecTraffic {
		startRecording(outputDir)
	}

	recvWg.Add(2)
	go setupReceiver(config.IfaceA, proto)
	go setupReceiver(config.IfaceB, proto)

	sendRatePerTarget := float64(time.Second / (200 * time.Millisecond))
	batchSize := int(float64(config.MaxSendRate) / sendRatePerTarget)
	batchCount := int(math.Ceil(float64(len(targets)) / float64(batchSize)))
	runTime := time.Duration(0)
	for i := 0; i < len(targets); i += batchSize {
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		batch := targets[i:end]
		batchIndex := int(math.Ceil(float64(end) / float64(batchSize)))
		log.Printf("Processing Batch (%d/%d): len=%d start=%d end=%d ", batchIndex, batchCount, len(batch), i, end)

		startProbing := time.Now()
		probingWg.Add(len(batch))
		for _, target := range batch {
			go probeTarget(senderA, senderB, rawIPLayers, target, proto)
		}
		probingWg.Wait()
		runTime += time.Since(startProbing)

		//printResults()
		saveResults(outputFile)

		results.Clear()
		recvChans.Clear()
	}
	log.Printf("Finished all batches: runtime=%v", runTime)

	close(stopReceiving)
	recvWg.Wait()

	if config.RecTraffic {
		stopRecording()
	}

	log.Println("Results saved to", outputFile.Name())
	log.Println("Command for Postprocessing: sudo python3 postprocessing.py", msmId)
	err := outputFile.Close()
	if err != nil {
		panic(err)
	}
}

// Probe
func createProbe(target string, key uint16, sentTime int64) {
	probes := getProbes(target)

	probe := &Probe{
		SentTime: sentTime,
	}

	probes.Store(key, probe)
}

func getProbe(target string, key uint16) (*Probe, bool) {
	probes := getProbes(target)

	probe, ok := probes.Load(key)
	if !ok {
		//log.Printf("Probe not created") // Commented out because it gets called frequently due to many incomplete target probes
		return nil, false
	}

	return probe.(*Probe), true
}

func getProbes(target string) *sync.Map {
	innerMap, ok := results.Load(target)
	if !ok {
		log.Printf("Target map not created")
		return nil
	}
	resultMap := innerMap.(*sync.Map)
	return resultMap
}

// Probing
func probeTarget(senderA Sender, senderB Sender, rawIPLayers []layers.IPv4, target string, proto Protocol) {
	defer probingWg.Done()

	dstIP := net.ParseIP(target).To4()
	payloads := buildPackets(rawIPLayers, dstIP, proto)

	attempts := 3

restartProbing:
	createRecvChan(target)
	recvCh, _ := getRecvChan(target)
	recvCounter := 0
	for seq := uint16(0); seq < config.ProbeCount; seq++ {
		sendPacket(senderA, senderB, payloads[seq], target, seq)
		if receivePacket(recvCh, target, seq, proto) {
			recvCounter++
		} else {
			if attempts == 0 {
				break
			} else {
				attempts--
				goto restartProbing
			}
		}
	}

	deleteRecvChan(target)
	//log.Printf("Finished probing target=%s received=%d/%d", target, recvCounter, config.ProbeCount)
}

// Send
func setupSender(iface Iface) Sender {
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

	fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(HToNS(syscall.ETH_P_ALL)))
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

	return Sender{
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

func HToNS(i uint16) uint16 {
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

func sendPacket(senderA Sender, senderB Sender, payload []byte, target string, seq uint16) {
	var sender Sender
	if seq%2 == 0 {
		sender = senderA
	} else {
		sender = senderB
	}

	sender.Send(payload)
	createProbe(target, seq, time.Now().UnixNano())
	//log.Printf("Request: target=%s seq=%d\n", target, seq)
}

// Receive
func setupReceiver(iface Iface, proto Protocol) {
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
			go addToRecvChan(ReplyInfo{
				Packet: packet,
				Time:   time.Now().UnixNano(),
			})
		case <-stopReceiving:
			return
		}
	}
}

func receivePacket(recvCh chan ReplyInfo, target string, seq uint16, proto Protocol) bool {
	timeout := time.After(config.MaxRTT)
	for {
		select {
		case replyInfo := <-recvCh:
			return processPacket(replyInfo, target, seq, proto)
		case <-timeout:
			return false
		}
	}
}

// Receive Channel
func createRecvChan(target string) {
	results.Store(target, &sync.Map{})
	recvChans.Store(target, make(chan ReplyInfo))
}

func deleteRecvChan(target string) {
	recvChans.Delete(target)
}

func getRecvChan(target string) (chan ReplyInfo, bool) {
	ch, ok := recvChans.Load(target)
	if !ok {
		return nil, false
	}
	return ch.(chan ReplyInfo), true
}

func addToRecvChan(replyInfo ReplyInfo) {
	if ipLayer := replyInfo.Packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ch, ok := getRecvChan(ip.SrcIP.String())
		if ok {
			ch <- replyInfo
		}
	}
}

// Process
func processPacket(replyInfo ReplyInfo, expSrc string, expSeq uint16, proto Protocol) bool {
	ok, src, ipId := checkIPLayer(replyInfo.Packet)
	if !ok {
		log.Println("IPv4 layer invalid")
		return false
	}

	if src != expSrc {
		log.Println("Src is not expected")
		return false
	}

	ok, seq := proto.CheckLayer(replyInfo.Packet)
	if !ok {
		log.Println("Protocol layer invalid")
		return false
	}

	if seq != expSeq {
		log.Printf("Seq is not expected (seq=%d exp=%d)", seq, expSeq)
		return false
	}

	probe, ok := getProbe(src, seq)
	if !ok {
		log.Println("No entry for probe")
		return false
	}

	if probe.IsValid {
		log.Println("Already received reply")
		return false
	}

	rtt := time.Duration(replyInfo.Time - probe.SentTime)
	if rtt >= config.MaxRTT {
		log.Printf("RTT too high (rtt=%v, src=%s)", rtt, src)
		return false
	}

	probe.ReceivedTime = replyInfo.Time
	probe.IpId = ipId
	probe.IsValid = true
	//log.Printf("Reply: src=%s seq=%d rtt=%v ipid=%d\n", src, seq, rtt, ipId)
	return true
}

// Output
func printResults() {
	log.Println("Results")
	results.Range(func(targetKey, resultMap interface{}) bool {
		target := targetKey.(string)
		log.Printf("  ip=%s\n", target)
		for seq := uint16(0); seq < config.ProbeCount; seq++ {
			probe, ok := getProbe(target, seq)
			if !ok {
				log.Printf("    seq=%d (no data available)\n", seq)
				continue
			}
			var rtt time.Duration
			if probe.IsValid {
				rtt = time.Duration(probe.ReceivedTime - probe.SentTime)
			} else {
				rtt = 0
			}
			log.Printf("    seq=%d ipid=%d rtt=%v isvalid=%v\n", seq, probe.IpId, rtt, probe.IsValid)
		}
		return true
	})
}

func createOutputDir() (string, string) {
	protoInfo := config.Protocol
	switch protoInfo {
	case "tcp":
		protoInfo += fmt.Sprintf("_%d", config.TcpDstPort)
	case "udp":
		protoInfo += "_53"
	}

	timeStamp := time.Now().Format("020106_150405")
	msmId := fmt.Sprintf("slow/%s/%s/%s", config.Targets, protoInfo, timeStamp)
	dir := fmt.Sprintf("../measurements/%s", msmId)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		panic(err)
	}
	return dir, msmId
}

func createOutputFile(outputDir string) *os.File {
	file, err := os.Create(fmt.Sprintf("%s/probing.csv", outputDir))
	if err != nil {
		panic(err)
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"IP", "OS", "IPID-Sequence", "SentTime-Sequence", "ReceivedTime-Sequence", "IsValid-Sequence"})

	return file
}

func saveResults(outputFile *os.File) {
	writer := csv.NewWriter(outputFile)
	defer writer.Flush()

	results.Range(func(targetKey, resultMap interface{}) bool {
		target := targetKey.(string)
		operatingSystem := targetsToOs[target]
		var ipIds, sentTimes, receivedTimes, isValids []string
		for seq := uint16(0); seq < config.ProbeCount; seq++ {
			probe, ok := getProbe(target, seq)
			if !ok {
				createProbe(target, seq, 0)
				probe, _ = getProbe(target, seq)
			}

			ipIds = append(ipIds, strconv.Itoa(int(probe.IpId)))
			sentTimes = append(sentTimes, strconv.Itoa(int(probe.SentTime)))
			receivedTimes = append(receivedTimes, strconv.Itoa(int(probe.ReceivedTime)))
			isValids = append(isValids, formatBool(probe.IsValid))
		}

		err := writer.Write([]string{
			target, operatingSystem,
			fmt.Sprintf("(%s)", joinWithComma(ipIds)),
			fmt.Sprintf("(%s)", joinWithComma(sentTimes)),
			fmt.Sprintf("(%s)", joinWithComma(receivedTimes)),
			fmt.Sprintf("(%s)", joinWithComma(isValids)),
		})
		if err != nil {
			panic(err)
		}
		return true
	})
}

func joinWithComma(items []string) string {
	return strings.Join(items, ",")
}

func formatBool(b bool) string {
	if b {
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
}

func loadTargets(fileName string) []string {
	file, openErr := os.Open("../targets/" + fileName + ".csv")
	if openErr != nil {
		panic(openErr)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	_, headerErr := reader.Read()
	if headerErr != nil {
		panic(headerErr)
	}

	records, rowErr := reader.ReadAll()
	if rowErr != nil {
		panic(rowErr)
	}

	var targets []string
	targetsToOs = make(map[string]string)
	for _, record := range records {
		ip := net.ParseIP(record[0])
		if ip == nil || ip.To4() == nil {
			continue
		}

		targets = append(targets, record[0])
		if len(record) > 1 {
			targetsToOs[record[0]] = record[1]
		} else {
			targetsToOs[record[0]] = ""
		}
	}

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})

	return targets
}

func loadProtocol(protocol string) Protocol {
	switch protocol {
	case "icmp":
		return ICMP
	case "tcp":
		return TCP
	case "udp":
		return UDP
	default:
		panic("Unknown protocol")
	}
}

// Build
func buildPackets(rawIPLayers []layers.IPv4, dstIP net.IP, proto Protocol) [][]byte {
	for i := range rawIPLayers {
		rawIPLayers[i].DstIP = dstIP
	}
	return proto.CreateLayers(rawIPLayers)
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
func createRawIPLayers(proto Protocol) []layers.IPv4 {
	ipLayers := make([]layers.IPv4, config.ProbeCount)

	for seq := uint16(0); seq < config.ProbeCount; seq++ {
		var srcIP net.IP
		if seq%2 == 0 {
			srcIP = srcAIp
		} else {
			srcIP = srcBIp
		}

		id := config.DefaultIpId
		if config.DetectMirror {
			id = config.MirrorIpIds[int(seq)%len(config.MirrorIpIds)]
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

func checkIPLayer(packet gopacket.Packet) (bool, string, uint16) {
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		log.Println("IPv4 layer invalid")
		return false, "", 0
	}

	if !ip.DstIP.Equal(srcAIp) && !ip.DstIP.Equal(srcBIp) {
		log.Println("DstIP not match")
		return false, "", 0
	}

	return true, ip.SrcIP.String(), ip.Id
}

// ICMP
func createICMPLayers(ipLayers []layers.IPv4) [][]byte {
	pList := make([][]byte, config.ProbeCount)

	for seq := uint16(0); seq < config.ProbeCount; seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Seq:      seq,
		}

		pList[seq] = buildLayers(&ipLayer, &pLayer)
	}
	return pList
}

func checkICMPLayer(packet gopacket.Packet) (bool, uint16) {
	if icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		if icmp.TypeCode == layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
			if icmp.Seq < config.ProbeCount {
				return true, icmp.Seq
			}
		}
	}
	return false, 0
}

// TCP
func createTCPLayers(ipLayers []layers.IPv4) [][]byte {
	pList := make([][]byte, config.ProbeCount)

	for seq := uint32(0); seq < uint32(config.ProbeCount); seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.TCP{
			SrcPort: layers.TCPPort(seq + config.TcpSrcPortOff),
			DstPort: config.TcpDstPort,
			Seq:     seq,
			SYN:     true,
			ACK:     config.TcpSA,
		}
		err := pLayer.SetNetworkLayerForChecksum(&ipLayer)
		if err != nil {
			panic(err)
		}

		pList[seq] = buildLayers(&ipLayer, &pLayer)
	}
	return pList
}

func checkTCPLayer(packet gopacket.Packet) (bool, uint16) {
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		if uint16(tcp.Ack-1) < config.ProbeCount {
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
func createUDPLayers(ipLayers []layers.IPv4) [][]byte {
	pList := make([][]byte, config.ProbeCount)

	for seq := uint16(0); seq < config.ProbeCount; seq++ {
		ipLayer := ipLayers[seq]
		pLayer := layers.UDP{
			SrcPort: layers.UDPPort(seq + config.UdpSrcPortOff),
			DstPort: 53,
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

		pList[seq] = buildLayers(&ipLayer, &pLayer, &dnsLayer)
	}
	return pList
}

func checkUDPLayer(packet gopacket.Packet) (bool, uint16) {
	if _, udpOk := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); udpOk {
		if dns, dnsOk := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); dnsOk {
			if _, icmpOk := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); !icmpOk {
				if dns.QR {
					if dns.ID < config.ProbeCount {
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
		outputFile := fmt.Sprintf("%s/%s.pcap", outputDir, iface.Name)
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
func setRSTDrop(enable bool) {
	var cmd *exec.Cmd

	if enable {
		cmd = exec.Command("bash", "-c", "sudo iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP > /dev/null 2>&1 || sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
	} else {
		cmd = exec.Command("bash", "-c", "sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
	}

	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

// Measurement
func measureSingleProtocol() {

}

func measureAllProtocols() {

}
