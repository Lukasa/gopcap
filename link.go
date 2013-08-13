package gopcap

// EthernetFrame represents a single ethernet frame. Valid only when the LinkType is ETHERNET.
type EthernetFrame struct {
	MACSource      [6]byte
	MACDestination [6]byte
	VLANTag        uint32
	Length         uint16
	EtherType      uint16
	data           []byte
}

func (e *EthernetFrame) Data() []byte {
	return e.data
}
