/*
gopcap is pure-Go implementation of a parser for .pcap files. Written from the
ground up for plugging directly into other components, the API is focused on
simplicity and clarity. To this end, it exposes the barest minimum of
functionality in as clear an API as possible.
*/
package gopcap

import (
	"errors"
	"io"
	"time"
)

// Errors
var NotAPcapFile error = errors.New("Not a pcap file.")
var InsufficientLength error = errors.New("Insufficient length.")
var UnexpectedEOF error = errors.New("Unexpected EOF.")

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
	Data        LinkLayer
}

// LinkLayer is a non-specific representation of a single link-layer level datagram, e.g. an Ethernet
// frame. It provides an abstract interface for pulling the lower layers out without specific knowledge
// of the structure of the link-layer in question.
type LinkLayer interface {
	LinkData() []byte
	FromBytes(data []byte) error
}

// Parse is the external API of gopcap. It takes anything that implements the
// io.Reader interface, but will mostly expect a file produced by anything that
// produces .pcap files. It will attempt to parse the entire file. If an error
// is encountered, as much of the parsed content as is possible will be returned,
// along with an error value.
func Parse(src io.Reader) (PcapFile, error) {
	file := new(PcapFile)

	// Check whether this is a libpcap file at all, and if so what byte ordering it has.
	_, flipped, err := checkMagicNum(src)
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
		err = parsePacket(pkt, src, flipped, file.LinkType)
		file.Packets = append(file.Packets, *pkt)
	}

	// EOF is a safe error, so switch that to nil.
	if err == io.EOF {
		err = nil
	}

	return *file, err
}
