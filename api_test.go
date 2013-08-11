package gopcap

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// Test the overall parsing functionality using the packaged testing .cap file.
func TestParse(t *testing.T) {
	src, err := os.Open("SkypeIRC.cap")
	if err != nil {
		t.Error("Missing pcap file.")
	}

	parsed, err := Parse(src)

	// Check the file header.
	if parsed.MajorVersion != uint16(2) {
		t.Errorf("Incorrectly parsed major version: expected %v, got %v.", 2, parsed.MajorVersion)
	}
	if parsed.MinorVersion != uint16(4) {
		t.Errorf("Incorrectly parsed minor version: expected %v, got %v.", 4, parsed.MinorVersion)
	}
	if parsed.TZCorrection != int32(0) {
		t.Errorf("Got nonzero TZ correction: %v.", parsed.TZCorrection)
	}
	if parsed.SigFigs != uint32(0) {
		t.Errorf("Got nonzero sig figs: %v.", parsed.SigFigs)
	}
	if parsed.MaxLen != uint32(65535) {
		t.Errorf("Incorrectly parsed maximum len: expected %v, got %v.", 65535, parsed.MaxLen)
	}
	if parsed.LinkType != ETHERNET {
		t.Errorf("Incorrect link type: expected %v, got %v.", ETHERNET, parsed.LinkType)
	}
	if len(parsed.Packets) != 2264 {
		t.Errorf("Unexpected number of packets: expected %v, got %v.", 2264, len(parsed.Packets))
	}

	// Check the packet header from the first packet. Including the raw data is a lousy way to test, but
	// at least the packet is small.
	packet := parsed.Packets[0]
	correct_ts := 321259*time.Hour + 31*time.Minute + 6*time.Second + 654*time.Millisecond + 692*time.Microsecond
	data := []byte{
		0, 22, 227, 25, 39, 21, 0, 4, 118, 150, 123, 218, 8, 0, 69, 0, 0, 82, 118, 237, 64, 0, 64,
		6, 86, 207, 192, 168, 1, 2, 212, 204, 214, 114, 11, 32, 26, 11, 77, 200, 78, 237, 84, 241,
		16, 114, 128, 24, 31, 75, 109, 46, 0, 0, 1, 1, 8, 10, 0, 216, 234, 72, 130, 228, 218, 176,
		73, 83, 79, 78, 32, 84, 104, 117, 110, 102, 105, 115, 99, 104, 32, 83, 109, 105, 108, 101,
		121, 32, 83, 109, 105, 108, 101, 121, 71, 10,
	}

	if packet.Timestamp != correct_ts {
		t.Errorf("Unexpected TS: expected %v, got %v.", correct_ts, packet.Timestamp)
	}
	if packet.IncludedLen != uint32(96) {
		t.Errorf("Unexpected included length: expected %v, got %v.", 96, packet.IncludedLen)
	}
	if packet.ActualLen != uint32(96) {
		t.Errorf("Unexpected actual length: expected %v, got %v.", 96, packet.ActualLen)
	}
	if bytes.Compare(packet.Data, data) != 0 {
		t.Errorf("Non-matching packet data:\n\texpected %v\n\tgot %v", data, packet.Data)
	}
}
