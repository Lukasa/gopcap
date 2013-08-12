package gopcap

import (
	"testing"
	"time"
)

type ByteReader []byte

func (r ByteReader) Read(p []byte) (int, error) {
	n := copy(p, r)
	return n, nil
}

func TestCheckMagicNum(t *testing.T) {
	in := []ByteReader{
		ByteReader{0xa1, 0xb2, 0xc3, 0xd4},
		ByteReader{0xd4, 0xc3, 0xb2, 0xa1},
		ByteReader{0xd4, 0xc3, 0xb2, 0xa0},
		ByteReader{0xd4, 0xc3, 0xb2},
	}

	first := []bool{true, true, false, false}
	second := []bool{false, true, false, false}
	third := []error{nil, nil, NotAPcapFile, InsufficientLength}

	for i, input := range in {
		out1, out2, out3 := checkMagicNum(input)

		if out1 != first[i] {
			t.Errorf("Unexpected first return val: expected %v, got %v.", first[i], out1)
		}

		if out2 != second[i] {
			t.Errorf("Unexpected second return val: expected %v, got %v.", second[i], out2)
		}

		if out3 != third[i] {
			t.Errorf("Unexpected third return val: expected %v, got %v.", third[i], out3)
		}
	}
}

func TestPopulatePacketHeaderGood(t *testing.T) {
	in := ByteReader{0xfa, 0x4f, 0xef, 0x44, 0x64, 0xfd, 0x09, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00}
	pkt := new(Packet)
	err := populatePacketHeader(pkt, in, true)
	correct_ts := 321259*time.Hour + 31*time.Minute + 6*time.Second + 654*time.Millisecond + 692*time.Microsecond

	if err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}
	if pkt.Timestamp != correct_ts {
		t.Errorf("Incorrect timestamp: expected %v, got %v", correct_ts, pkt.Timestamp)
	}
	if pkt.IncludedLen != uint32(96) {
		t.Errorf("Incorrect included length: expected %v, got %v", 96, pkt.IncludedLen)
	}
	if pkt.ActualLen != uint32(96) {
		t.Errorf("Incorrect actual length: expected %v, got %v", 96, pkt.ActualLen)
	}
}
