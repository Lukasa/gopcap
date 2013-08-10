package gopcap

import "encoding/binary"

// getUint16 takes a two-element byte slice and returns the uint16 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getUint16(buf []byte, flipped bool) uint16 {
	num := uint16(0)
	first, second := 0, 1

	if flipped {
		first, second = 1, 0
	}

	num = (uint16(buf[first]) << 8) + uint16(buf[second])

	return num
}

// getUint32 takes a four-element byte slice and returns the uint32 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getUint32(buf []byte, flipped bool) uint32 {
	num := uint32(0)
	first, second, third, fourth := 0, 1, 2, 3

	if flipped {
		first, second, third, fourth = 3, 2, 1, 0
	}

	num = (uint32(buf[first]) << 24) + (uint32(buf[second]) << 16) + (uint32(buf[third]) << 8) + uint32(buf[fourth])

	return num
}

// getInt32 takes a four-element byte slice and returns the Int32 contained within it. If flipped
// is set, assumes the byte order is reversed.
func getInt32(buf []byte, flipped bool) int32 {
	var num int64

	if !flipped {
		num, _ = binary.Varint(buf)
	} else {
		num, _ = binary.Varint([]byte{buf[3], buf[2], buf[1], buf[0]})
	}

	return int32(num)
}
