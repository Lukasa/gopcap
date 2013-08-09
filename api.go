/*
gopcap is pure-Go implementation of a parser for .pcap files. Written from the
ground up for plugging directly into other components, the API is focused on
simplicity and clarity. To this end, it exposes the barest minimum of
functionality in as clear an API as possible.
*/
package gopcap

import (
	"bytes"
	"errors"
	"io"
	"time"
)

// Link encodes a given Link-Layer header type. See http://www.tcpdump.org/linktypes.html for a more-full
// explanation of each header type.
type Link uint32

const (
	NULL                       Link = 0
	ETHERNET                   Link = 1
	AX25                       Link = 3
	IEEE802_5                  Link = 6
	ARCNET_BSD                 Link = 7
	SLIP                       Link = 8
	PPP                        Link = 9
	FDDI                       Link = 10
	PPP_HDLC                   Link = 50
	PPP_ETHER                  Link = 51
	ATM_RFC1483                Link = 100
	RAW                        Link = 101
	C_HDLC                     Link = 104
	IEEE802_11                 Link = 105
	FRELAY                     Link = 107
	LOOP                       Link = 108
	LINUX_SLL                  Link = 113
	LTALK                      Link = 114
	PFLOG                      Link = 117
	IEEE802_11_PRISM           Link = 119
	IP_OVER_FC                 Link = 122
	SUNATM                     Link = 123
	IEEE802_11_RADIOTAP        Link = 127
	ARCNET_LINUX               Link = 129
	APPLE_IP_OVER_IEEE1394     Link = 138
	MTP2_WITH_PHDR             Link = 139
	MTP2                       Link = 140
	MTP3                       Link = 141
	SCCP                       Link = 142
	DOCSIS                     Link = 143
	LINUX_IRDA                 Link = 144
	IEEE802_11_AVS             Link = 163
	BACNET_MS_TP               Link = 165
	PPP_PPPD                   Link = 166
	GPRS_LLC                   Link = 169
	LINUX_LAPD                 Link = 177
	BLUETOOTH_HCI_H4           Link = 187
	USB_LINUX                  Link = 189
	PPI                        Link = 192
	IEEE802_15_4               Link = 195
	SITA                       Link = 196
	ERF                        Link = 197
	BLUETOOTH_HCI_H4_WITH_PHDR Link = 201
	AX25_KISS                  Link = 202
	LAPD                       Link = 203
	PPP_WITH_DIR               Link = 204
	C_HDLC_WITH_DIR            Link = 205
	FRELAY_WITH_DIR            Link = 206
	IPMB_LINUX                 Link = 209
	IEEE802_15_4_NONASK_PHY    Link = 215
	USB_LINUX_MMAPPED          Link = 220
	FC_2                       Link = 224
	FC_2_WITH_FRAME_DELIMS     Link = 225
	IPNET                      Link = 226
	CAN_SOCKETCAN              Link = 227
	IPV4                       Link = 228
	IPV6                       Link = 229
	IEEE802_15_4_NOFCS         Link = 230
	DBUS                       Link = 231
	DVB_CI                     Link = 235
	MUX27010                   Link = 236
	STANAG_5066_D_PDU          Link = 237
	NFLOG                      Link = 239
	NETANALYZER                Link = 240
	NETANALYZER_TRANSPARENT    Link = 241
	IPOIB                      Link = 242
	MPEG_2_TS                  Link = 243
	NG40                       Link = 244
	NFC_LLCP                   Link = 245
	INFINIBAND                 Link = 247
	SCTP                       Link = 248
	USBPCAP                    Link = 249
	RTAC_SERIAL                Link = 250
	BLUETOOTH_LE_LL            Link = 251
)

// PcapFile represents the parsed form of a single .pcap file. The structure
// contains some details about the file itself, but is mostly a container for
// the parsed Packets.
type PcapFile struct {
	MajorVersion uint16
	MinorVersion uint16
	TZCorrection int32 // In seconds east of UTC
	SigFigs      uint32
	MaxLen       uint32
	LinkType     Link
	Packets      []Packet
}

// Packet is a representation of a single network packet. The structure
// contains the timestamp on the packet, some information about packet size,
// and the recorded bytes from the packet.
type Packet struct {
	Timestamp   time.Duration
	IncludedLen uint32
	ActualLen   uint32
	Data        []byte
}

// Parse is the external API of gopcap. It takes anything that implements the
// io.Reader interface, but will mostly expect a file produced by anything that
// produces .pcap files. It will attempt to parse the entire file. If an error
// is encountered, as much of the parsed content as is possible will be returned,
// along with an error value.
func Parse(src io.Reader) (PcapFile, error) {
	file := new(PcapFile)

	// Check whether this is a libpcap file at all, and if so what byte ordering it has.
	cont, flipped, err := checkMagicNum(src)
	if err != nil {
		return *file, err
	}

	// Then populate the file header.
	err = populateFileHeader(file, src, flipped)
	if err != nil {
		return *file, err
	}

	// Whatever remains now are packets. Parse the rest of the file.
	file.Packets = make([]Packet, 0)

	for err == nil {
		pkt := new(Packet)
		err = parsePacket(pkt, src, flipped)
		file.Packets = append(file.Packets, *pkt)
	}

	// EOF is a safe error, so switch that to nil.
	if err == io.EOF {
		err = nil
	}

	return *file, err
}

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

	return false, false, errors.New("Not a pcap file.")
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
