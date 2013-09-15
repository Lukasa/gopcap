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
}
