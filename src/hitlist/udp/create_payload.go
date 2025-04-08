package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"os"
)

func main() {
	// Define the files and corresponding payloads
	payloads := map[string][]byte{
		"dns.bin":  generateDNSRequest(),
		"ntp.bin":  generateNTPRequest(),
		"snmp.bin": generateSNMPRequest(),
	}

	// Iterate over all files and save the payloads
	for filename, payload := range payloads {
		err := saveToFile(filename, payload)
		if err != nil {
			log.Fatalf("Error creating file %s: %v", filename, err)
		}
		fmt.Printf("File '%s' successfully created.\n", filename)
	}
}

// Generate the DNS request as a byte slice
func generateDNSRequest() []byte {
	seq := uint16(1)
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

	// Serialize the DNS request
	dnsRequest, err := serializeLayer(&dnsLayer)
	if err != nil {
		log.Fatal(err)
	}
	return dnsRequest
}

// Generate the NTP request as a byte slice
func generateNTPRequest() []byte {
	return []byte{
		0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NTP Request Header
	}
}

// Generate the SNMP request as a byte slice
func generateSNMPRequest() []byte {
	return []byte{
		0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x10, 0x30, 0x0e, 0x02, 0x04, 0x71, 0x01, 0x01, 0x01, 0x02,
		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0f, 0x02, 0x04, 0x71, 0x01, 0x01, 0x01, 0x05, 0x00, 0x00,
	}
}

// Serialize layers and return the binary data
func serializeLayer(layer gopacket.SerializableLayer) ([]byte, error) {
	pBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(pBuf, opts, layer)
	if err != nil {
		return nil, err
	}
	return pBuf.Bytes(), nil
}

// Save binary data to a file
func saveToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}
