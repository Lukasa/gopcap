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
