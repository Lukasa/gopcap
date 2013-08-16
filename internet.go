package gopcap

//-------------------------------------------------------------------------------------------
// IPv4
//-------------------------------------------------------------------------------------------

type IPv4Packet struct {
	IHL            uint8
	DSCP           uint8
	ECN            uint8
	TotalLength    uint16
	ID             uint16
	DontFragment   bool
	MoreFragments  bool
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SourceAddress  []byte
	DestAddress    []byte
	Options        []byte
	data           []byte
}

func (p *IPv4Packet) InternetData() []byte {
	return p.data
}

func (p *IPv4Packet) FromBytes(data []byte) error {
	// The IPv4 header is full of crazy non-aligned fields that I've expanded in the structure.
	// This makes this function a total nightmare. My apologies in advance.

	// Check that we have enough data for the header, at the very least.
	if len(data) < 20 {
		return InsufficientLength
	}

	// Check that this actually is an IPv4 packet.
	if ((uint8(data[0]) & 0xF0) >> 4) != uint8(4) {
		return IncorrectPacket
	}

	// The header length is the low four bits of the first byte.
	p.IHL = uint8(data[0]) & 0x0F

	// The DSCP is the high six(!) bits of the second byte.
	p.DSCP = (uint8(data[1]) & 0xFC) >> 2

	// Congestion notification is the low two bits of the second byte.
	p.ECN = uint8(data[1]) & 0x03

	// Total length is saner: 16-bit integer.
	p.TotalLength = getUint16(data[2:4], false)

	// Same with the ID.
	p.ID = getUint16(data[4:6], false)

	// Back to the crazy with the flags: the top three bits of the 7th byte. We only care
	// about bits two and three. It hurt me to write that sentence.
	if (uint8(data[6]) & 0x40) != 0 {
		p.DontFragment = true
	} else if (uint8(data[6]) & 0x20) != 0 {
		p.MoreFragments = true
	}

	// Following from the flag crazy, the fragment offset is the low 13 bits of the 7th
	// and 8th bytes.
	p.FragmentOffset = getUint16(data[6:8], false) & 0x1FFF

	// The remaining fields are fairly sensible. TTL is the 9th byte.
	p.TTL = uint8(data[8])

	// Protocol is the tenth.
	p.Protocol = uint8(data[9])

	// Header checksum is eleven and twelve.
	p.Checksum = getUint16(data[10:12], false)

	// Then the source IP and destination IP.
	p.SourceAddress = data[12:16]
	p.DestAddress = data[16:20]

	// If IHL is more than 5, we have (IHL - 5) * 4 bytes of options.
	if p.IHL > 5 {
		optionLength := uint16(p.IHL-5) * 4
		p.Options = data[20 : 20+optionLength]

		// Reslice data so that the actual packet contents still start at offset 20.
		data = data[optionLength:]
	}

	// The data length is the total length, minus the headers. The headers are, for no good
	// reason, measured in 32-bit words, so the data length is actually:
	dataLen := p.TotalLength - (uint16(p.IHL) * 4)
	if len(data[20:]) != int(dataLen) {
		return IncorrectPacket
	}

	p.data = data[20:]
	return nil
}
