/*
gopcap is pure-Go implementation of a parser for .pcap files. Written from the
ground up for plugging directly into other components, the API is focused on
simplicity and clarity. To this end, it exposes the barest minimum of
functionality in as clear an API as possible.
*/
package gopcap

import (
	"io"
)

// PcapFile represents the parsed form of a single .pcap file. The structure
// contains some details about the file itself, but is mostly a container for
// the parsed Packets.
type PcapFile struct{}

// Packet is a representation of a single network packet. The structure
// contains the timestamp on the packet, some information about packet size,
// and the recorded bytes from the packet.
type Packet struct{}

// Parse is the external API of gopcap. It takes anything that implements the
// io.Reader interface, but will mostly expect a file produced by anything that
// produces .pcap files. It will attempt to parse the entire file. If an error
// is encountered, as much of the parsed content as is possible will be returned,
// along with an error value.
func Parse(src io.Reader) (*PcapFile, error) {}
