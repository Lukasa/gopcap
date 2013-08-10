package gopcap

import "testing"

func TestGetUint16(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12},
		[]byte{0xff, 0x01},
		[]byte{0x09, 0x0a},
	}

	out_not_flipped := []uint16{
		uint16(39186),
		uint16(65281),
		uint16(2314),
	}

	out_flipped := []uint16{
		uint16(4761),
		uint16(511),
		uint16(2569),
	}

	for i, input := range in {
		out1 := getUint16(input, false)
		out2 := getUint16(input, true)

		if out1 != out_not_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_not_flipped[i], out1)
		}

		if out2 != out_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_flipped[i], out2)
		}
	}
}
