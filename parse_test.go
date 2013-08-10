package gopcap

import "testing"

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
