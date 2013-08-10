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

func TestGetUint32(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12, 0x66, 0x00},
		[]byte{0xff, 0x01, 0x08, 0xdd},
		[]byte{0x09, 0x0a, 0x12, 0x66},
	}

	out_not_flipped := []uint32{
		uint32(2568119808),
		uint32(4278257885),
		uint32(151655014),
	}

	out_flipped := []uint32{
		uint32(6689433),
		uint32(3708289535),
		uint32(1712458249),
	}

	for i, input := range in {
		out1 := getUint32(input, false)
		out2 := getUint32(input, true)

		if out1 != out_not_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_not_flipped[i], out1)
		}

		if out2 != out_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_flipped[i], out2)
		}
	}
}

func TestGetInt32(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12, 0x66, 0x00},
		[]byte{0xff, 0x01, 0x08, 0xdd},
		[]byte{0x09, 0x0a, 0x12, 0x66},
	}

	out_not_flipped := []int32{
		int32(-1726847488),
		int32(-16709411),
		int32(151655014),
	}

	out_flipped := []int32{
		int32(6689433),
		int32(-586677761),
		int32(1712458249),
	}

	for i, input := range in {
		out1 := getInt32(input, false)
		out2 := getInt32(input, true)

		if out1 != out_not_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_not_flipped[i], out1)
		}

		if out2 != out_flipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", out_flipped[i], out2)
		}
	}
}
