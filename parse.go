package gopcap

import (
	"bytes"
	"errors"
	"io"
	"time"
)

// checkMagicNum checks the first four bytes of a pcap file, searching for the magic number
// and checking the byte order. Returns three values: whether the file is a pcap file, whether
// the byte order needs flipping, and any error that was encountered. If error is returned,
// the other values are invalid.
func checkMagicNum(src io.Reader) (bool, bool, error) {
	// These magic numbers form the header of a pcap file.
	magic := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	magic_reverse := []byte{0xd4, 0xc3, 0xb2, 0xa1}

	buffer := make([]byte, 4)
	read_count, err := src.Read(buffer)

	if err != nil {
		return false, false, err
	}
	if read_count != 4 {
		return false, false, errors.New("Insufficent length.")
	}

	if bytes.Compare(buffer, magic) == 0 {
		return true, false, nil
	} else if bytes.Compare(buffer, magic_reverse) == 0 {
		return true, true, nil
	}

	return false, false, NotAPcapFile
}

// parsePacket parses a full packet out of the pcap file. It returns an error if any problems were
// encountered.
func parsePacket(pkt *Packet, src io.Reader, flipped bool) error {
	err := populatePacketHeader(pkt, src, flipped)

	if err != nil {
		return err
	}

	data := make([]byte, pkt.IncludedLen)
	readlen, err := src.Read(data)
	pkt.Data = data

	if uint32(readlen) != pkt.IncludedLen {
		err = errors.New("Unexpected EOF")
	}

	return err
}

// populateFileHeader reads the next 20 bytes out of the .pcap file and uses it to populate the
// PcapFile structure.
func populateFileHeader(file *PcapFile, src io.Reader, flipped bool) error {
	buffer := make([]byte, 20)
	read_count, err := src.Read(buffer)

	if err != nil {
		return err
	} else if read_count != 20 {
		return errors.New("Insufficient length.")
	}

	// First two bytes are the major version number.
	file.MajorVersion = getUint16(buffer[0:2], flipped)

	// Next two are the minor version number.
	file.MinorVersion = getUint16(buffer[2:4], flipped)

	// GMT to local correction, in seconds east of UTC.
	file.TZCorrection = getInt32(buffer[4:8], flipped)

	// Next is the number of significant figures in the timestamps. Almost always zero.
	file.SigFigs = getUint32(buffer[8:12], flipped)

	// Now the maximum length of the captured packet data.
	file.MaxLen = getUint32(buffer[12:16], flipped)

	// And the link type.
	file.LinkType = Link(getUint32(buffer[16:20], flipped))

	return nil
}

// populatePacketHeader reads the next 16 bytes out of the file and builds it into a
// packet header.
func populatePacketHeader(packet *Packet, src io.Reader, flipped bool) error {
	buffer := make([]byte, 16)
	read_count, err := src.Read(buffer)

	if read_count != 16 {
		return errors.New("Insufficient length.")
	}

	// First is a pair of fields that build up the timestamp.
	ts_seconds := getUint32(buffer[0:4], flipped)
	ts_millis := getUint32(buffer[4:8], flipped)
	packet.Timestamp = (time.Duration(ts_seconds) * time.Second) + (time.Duration(ts_millis) * time.Millisecond)

	// Next is the length of the data segment.
	packet.IncludedLen = getUint32(buffer[8:12], flipped)

	// Then the original length of the packet.
	packet.ActualLen = getUint32(buffer[12:16], flipped)

	return err
}
