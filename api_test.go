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

	if packet.Timestamp != correct_ts {
		t.Errorf("Unexpected TS: expected %v, got %v.", correct_ts, packet.Timestamp)
	}
	if packet.IncludedLen != uint32(96) {
		t.Errorf("Unexpected included length: expected %v, got %v.", 96, packet.IncludedLen)
	}
	if packet.ActualLen != uint32(96) {
		t.Errorf("Unexpected actual length: expected %v, got %v.", 96, packet.ActualLen)
	}

	// This is definitely an ethernet frame. If this fails, we failed the test.
	frame := packet.Data.(*EthernetFrame)
	macSrc := []byte{0x00, 0x04, 0x76, 0x96, 0x7B, 0xDA}
	macDst := []byte{0x00, 0x16, 0xE3, 0x19, 0x27, 0x15}

	if bytes.Compare(frame.MACSource, macSrc) != 0 {
		t.Errorf("Unexpected source MAC: expected %v, got %v.", macSrc, frame.MACSource)
	}
	if bytes.Compare(frame.MACDestination, macDst) != 0 {
		t.Errorf("Unexpected destination MAC: expected %v, got %v.", macDst, frame.MACDestination)
	}
	if len(frame.VLANTag) != 0 {
		t.Errorf("Incorrectly received VLAN tag: %v", frame.VLANTag)
	}
	if frame.Length != 0 {
		t.Errorf("Incorrectly received length: %v", frame.Length)
	}
	if frame.EtherType != EtherType(2048) {
		t.Errorf("Unexpected EtherType: expected %v, got %v", 2048, frame.EtherType)
	}

	// This is definitely an IPv4 packet.
	pkt := frame.LinkData().(*IPv4Packet)
	expectedSrc := []byte{192, 168, 1, 2}
	expectedDst := []byte{212, 204, 214, 114}

	if pkt.IHL != uint8(5) {
		t.Errorf("Unexpected IHL: expected %v, got %v", 5, pkt.IHL)
	}
	if pkt.DSCP != uint8(0) {
		t.Errorf("Unexpected DSCP: expected %v, got %v", 0, pkt.DSCP)
	}
	if pkt.ECN != uint8(0) {
		t.Errorf("Unexpected ECN: expected %v, got %v", 0, pkt.ECN)
	}
	if pkt.TotalLength != uint16(82) {
		t.Errorf("Unexpected total length: expected %v, got %v", 82, pkt.TotalLength)
	}
	if pkt.ID != uint16(30445) {
		t.Errorf("Unexpected ID: expected %v, got %v", 30445, pkt.ID)
	}
	if !pkt.DontFragment {
		t.Error("Don't fragment bit unset.")
	}
	if pkt.MoreFragments {
		t.Errorf("More fragments bit set.")
	}
	if pkt.FragmentOffset != uint16(0) {
		t.Errorf("Unexpected fragment offset: expected %v, got %v", 0, pkt.FragmentOffset)
	}
	if pkt.TTL != uint8(64) {
		t.Errorf("Unexpected TTL: expected %v, got %v", 64, pkt.TTL)
	}
	if pkt.Protocol != IPP_TCP {
		t.Errorf("Unexpected protocol: expected %v, got %v", IPP_TCP, pkt.Protocol)
	}
	if pkt.Checksum != uint16(22223) {
		t.Errorf("Unexpected checksum: expected %v, got %v", 22223, pkt.Checksum)
	}
	if bytes.Compare(pkt.SourceAddress, expectedSrc) != 0 {
		t.Errorf("Unexpected source address: expected %v, got %v", expectedSrc, pkt.SourceAddress)
	}
	if bytes.Compare(pkt.DestAddress, expectedDst) != 0 {
		t.Errorf("Unexpected destination address: expected %v, got %v", expectedDst, pkt.DestAddress)
	}
	if len(pkt.Options) != 0 {
		t.Errorf("Shouldn't have any options: got %v", pkt.Options)
	}
}
