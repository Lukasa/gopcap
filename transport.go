package gopcap

//-----------------------------------------------------------------------------
// Unknown Transport
//-----------------------------------------------------------------------------

// UnknownTransport represents the data for a Transport-Layer packet that gopcap doesn't
// understand. It simply provides uninterpreted data representing the entire transport-layer
// packet.
type UnknownTransport struct {
	data []byte
}

func (u *UnknownTransport) TransportData() []byte {
	return u.data
}

func (u *UnknownTransport) FromBytes(data []byte) error {
	u.data = data
	return nil
}

//-----------------------------------------------------------------------------
// TCPSegment
//-----------------------------------------------------------------------------

// TCPSegment represents the data for a single Transmission Control Protocol segment. This method of
// storing a TCPSegment is less efficient than storing the binary representation on the wire.
type TCPSegment struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	HeaderSize      uint8
	NS              bool // This should be viewed as a temporary solution for flags: it's hugely space-inefficient,
	CWR             bool // and so I'll probably update the TCPSegment to handle flags differently.
	ECE             bool
	URG             bool
	ACK             bool
	PSH             bool
	RST             bool
	SYN             bool
	FIN             bool
	WindowSize      uint16
	Checksum        uint16
	UrgentOffset    uint16
	OptionData      []byte // This is temporary. We should handle TCP options properly.
	data            []byte
}

func (t *TCPSegment) TransportData() []byte {
	return t.data
}

func (t *TCPSegment) FromBytes(data []byte) error {
	// Begin by confirming that we have enough data for a complete TCP header.
	if len(data) < 20 {
		return InsufficientLength
	}

	// The first four fields are really easy.
	t.SourcePort = getUint16(data[0:2], false)
	t.DestinationPort = getUint16(data[2:4], false)
	t.SequenceNumber = getUint32(data[4:8], false)
	t.AckNumber = getUint32(data[8:12], false)

	// The header size is the top four bits of the next byte.
	t.HeaderSize = uint8(data[12]) >> 4

	// Now we have all the flag fields. First, the NS flag.
	if (uint8(data[12]) & 0x01) != 0 {
		t.NS = true
	}

	// The next eight flags are all in the next byte.
	flags := uint8(data[13])
	if (flags & 0x80) != 0 {
		t.CWR = true
	}
	if (flags & 0x40) != 0 {
		t.ECE = true
	}
	if (flags & 0x20) != 0 {
		t.URG = true
	}
	if (flags & 0x10) != 0 {
		t.ACK = true
	}
	if (flags & 0x08) != 0 {
		t.PSH = true
	}
	if (flags & 0x04) != 0 {
		t.RST = true
	}
	if (flags & 0x02) != 0 {
		t.SYN = true
	}
	if (flags & 0x01) != 0 {
		t.FIN = true
	}

	// Now we're back to sane things.
	t.WindowSize = getUint16(data[14:16], false)
	t.Checksum = getUint16(data[16:18], false)
	t.UrgentOffset = getUint16(data[18:20], false)

	// If the header size is larger than 5 (it's measured in 32-bit words for reasons that escape me),
	// we have some number of extra bytes that form the TCP options.
	extraBytes := (t.HeaderSize - 5) * 4
	data = data[20:]

	if len(data) < int(extraBytes) {
		return InsufficientLength
	}

	t.OptionData = data[:extraBytes]

	// All that remains is the contained data.
	t.data = data[extraBytes:]

	return nil
}

//-----------------------------------------------------------------------------
// UDPDatagram
//-----------------------------------------------------------------------------

// UDPDatagram represents the data for a single User Datagram Protocol datagram. This method of
// storing a UDPDatagram is less efficient than storing the binary representation on the wire.
type UDPDatagram struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
	data            []byte
}

func (u *UDPDatagram) TransportData() []byte {
	return u.data
}

func (u *UDPDatagram) FromBytes(data []byte) error {
	// Begin by confirming that we have enough data to actually represent a UDP datagram.
	if len(data) < 8 {
		return InsufficientLength
	}

	// Happily, UDP is super simple. This makes this code equally simple.
	u.SourcePort = getUint16(data[0:2], false)
	u.DestinationPort = getUint16(data[2:4], false)
	u.Length = getUint16(data[4:6], false)
	u.Checksum = getUint16(data[6:8], false)

	// All that remains is data.
	u.data = data[8:]

	return nil
}
