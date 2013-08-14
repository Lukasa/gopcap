package gopcap

// The minimum value of the EtherType field. If the value is less than this, it's a length.
// The above statement isn't entirely true, but it's true enough.
const minEtherType uint16 = 1536

//-------------------------------------------------------------------------------------------
// UnknownLink
//-------------------------------------------------------------------------------------------

// UnknownLink represents the data for a link type that gopcap doesn't understand. It simply
// provides uninterpreted data representing the entire link-layer packet.
type UnknownLink struct {
	data []byte
}

func (u *UnknownLink) LinkData() []byte {
	return u.data
}

func (u *UnknownLink) FromBytes(data []byte) error {
	u.data = data
	return nil
}

//-------------------------------------------------------------------------------------------
// EthernetFrame
//-------------------------------------------------------------------------------------------

// EthernetFrame represents a single ethernet frame. Valid only when the LinkType is ETHERNET.
type EthernetFrame struct {
	MACSource      []byte
	MACDestination []byte
	VLANTag        []byte
	Length         uint16
	EtherType      uint16
	data           []byte
}

func (e *EthernetFrame) LinkData() []byte {
	return e.data
}

// Given a series of bytes, populate the EthernetFrame structure.
func (e *EthernetFrame) FromBytes(data []byte) error {
	if len(data) <= 14 {
		return InsufficientLength
	}

	e.MACDestination = data[0:6]
	e.MACSource = data[6:12]

	// Check for a VLAN tag. If it's there, copy it and the reslice to keep the indices the
	// same through the rest of the function.
	if (data[12] == 0x81) && (data[13] == 0x00) {
		e.VLANTag = data[12:16]
		data = data[4:]
	}

	// Handle the length/EtherType nonsense.
	lenOrType := getUint16(data[12:14], false)
	if lenOrType >= minEtherType {
		e.EtherType = lenOrType
	} else {
		e.Length = lenOrType
	}

	// Everything else is payload data.
	e.data = data[14:]

	return nil
}
