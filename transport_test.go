package gopcap

import (
	"bytes"
	"testing"
)

func TestTCPGood(t *testing.T) {
	// Define some data.
	data := []byte{
		0x0B, 0x20, 0x1A, 0x0B, 0x4D, 0xC8, 0x4E, 0xED, 0x54, 0xF1, 0x10, 0x72, 0x80, 0x18, 0x1F, 0x4B, 0x6D, 0x2E, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A, 0x00, 0xD8,
		0xEA, 0x48, 0x82, 0xE4, 0xDA, 0xB0, 0x49, 0x53, 0x4F, 0x4E, 0x20, 0x54, 0x68, 0x75, 0x6E, 0x66, 0x69, 0x73, 0x63, 0x68, 0x20, 0x53, 0x6D, 0x69, 0x6C, 0x65,
		0x79, 0x20, 0x53, 0x6D, 0x69, 0x6C, 0x65, 0x79, 0x47, 0x0A,
	}
	optBytes := []byte{0x01, 0x01, 0x08, 0x0a, 0x00, 0xd8, 0xea, 0x48, 0x82, 0xe4, 0xda, 0xb0}
	pkt := new(TCPSegment)
	err := pkt.FromBytes(data)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if pkt.SourcePort != uint16(2848) {
		t.Errorf("Unexpected source port: expected %v, got %v", 2848, pkt.SourcePort)
	}
	if pkt.DestinationPort != uint16(6667) {
		t.Errorf("Unexpected destination port: expected %v, got %v", 6667, pkt.DestinationPort)
	}
	if pkt.SequenceNumber != uint32(1304973037) {
		t.Errorf("Unexpected sequence number: expected %v, got %v", 1304973037, pkt.SequenceNumber)
	}
	if pkt.AckNumber != uint32(1425084530) {
		t.Errorf("Unexpected ack number: expected %v, got %v", 1425084530, pkt.AckNumber)
	}
	if pkt.HeaderSize != uint8(8) {
		t.Errorf("Unexpected header size: expected %v, got %v", 8, pkt.HeaderSize)
	}
	if pkt.NS {
		t.Errorf("Expected NS flag not to be set and it was.")
	}
	if pkt.CWR {
		t.Errorf("Expected CWR flag not to be set and it was.")
	}
	if pkt.ECE {
		t.Errorf("Expected ECE flag not to be set and it was.")
	}
	if pkt.URG {
		t.Errorf("Expected URG flag not to be set and it was.")
	}
	if !pkt.ACK {
		t.Errorf("Expected ACK flag to be set and it wasn't.")
	}
	if !pkt.PSH {
		t.Errorf("Expected PSH flag to be set and it wasn't.")
	}
	if pkt.RST {
		t.Errorf("Expected RST flag not to be set and it was.")
	}
	if pkt.SYN {
		t.Errorf("Expected SYN flag not to be set and it was.")
	}
	if pkt.FIN {
		t.Errorf("Expected FIN flag not to be set and it was.")
	}
	if pkt.WindowSize != uint16(8011) {
		t.Errorf("Unexpected window size: expected %v, got %v", 8011, pkt.WindowSize)
	}
	if pkt.Checksum != 0x6d2e {
		t.Errorf("Unexpected checksum: expected %v, got %v", 0x6d2e, pkt.Checksum)
	}
	if pkt.UrgentOffset != uint16(0) {
		t.Errorf("Unexpected urgent offset: expected %v, got %v", 0, pkt.UrgentOffset)
	}
	if bytes.Compare(pkt.OptionData, optBytes) != 0 {
		t.Errorf("Unexpected option data: expected %v, got %v", optBytes, pkt.OptionData)
	}
	if len(pkt.TransportData()) != 30 {
		t.Errorf("Unexpected length of transport data: expected %v, got %v", 30, len(pkt.TransportData()))
	}
}
