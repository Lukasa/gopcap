package gopcap

// EthernetFrame represents a single ethernet frame. Valid only when the LinkType is ETHERNET.
type EthernetFrame struct {
	MACSource      []byte
	MACDestination []byte
	VLANTag        []byte
	Length         uint16
	EtherType      uint16
	data           []byte
}

func (e *EthernetFrame) Data() []byte {
	return e.data
}
