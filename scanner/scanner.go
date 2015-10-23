package scanner

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mediocregopher/radix.v2/redis"
)

var (
	device       string = "en1" // "eth0" //en1 wireless card on OSX
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func Scan() {
	fmt.Println("\n---- Scanner ----")

	// bytes := Make_Simple_Packet()
	// Decode_Data_Packet(bytes)

	Initialize_Redis_Client()

	// Read_PCAP_Packets_FromFile()
	Read_RAW_Socket_Data()

	fmt.Println("\ndone...")
}

func Initialize_Redis_Client() {
	//connect to redis server
	client, err := redis.Dial("tcp", "localhost:6379")
	if err != nil {
		fmt.Println("Problem connecting to Redis Server")
		log.Fatal(err)
	}
	// defer close
	defer client.Close()
}

//----- PCAP read from
func Read_RAW_Socket_Data() {
	fmt.Println("\tStarting live network traffic monitor (promiscuous mode)\n")
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		fmt.Println("Looks like there is an error getting live network stream. Try running it again with 'sudo' command")
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		process_gopacket(packet)
	}
}

//------ PCAP Print PCAP Data -----
func process_gopacket(packet gopacket.Packet) {

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet layer | Type: %s | Src_MAC: %s Dst_MAC: %s\n", ethernetPacket.EthernetType, ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		// fmt.Printf("\tIPv4 | %s | Src: %s Dest: %s \n", ip.Protocol, ip.SrcIP, ip.DstIP)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP

		//
		register_network_call_with_redis(ip.Protocol, ip.SrcIP, ip.DstIP)
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("\tTCP | From port %d to %d", tcp.SrcPort, tcp.DstPort)
		fmt.Println("| TCP Seq: ", tcp.Seq)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

//Call redis from here (running redis on local host right now)
func register_network_call_with_redis(protocolType layers.IPProtocol, src_ip net.IP, dst_ip net.IP) {
	fmt.Printf("\tIPv4 | %s | Src: %s Dest: %s \n", protocolType, src_ip, dst_ip)

	// client, err := redis.Dial("tcp", "localhost:6379")
	// if err != nil {
	// 	//handle
	// }
	// // defer close
	// defer client.Close()

	// err = client.Cmd("SET", src_ip, dst_ip).Err
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// foo, err := client.Cmd("GET", src_ip).Str()
	// if err != nil {
	// 	fmt.Println(err.Error())
	// } else {
	// 	fmt.Println(foo)
	// }
}

//---------- Test packets
func Make_Simple_Test_Packet() []byte {
	bytes := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, // magic, maj, min
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tz, sigfigs
		0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen, linkType
		0x5A, 0xCC, 0x1A, 0x54, 0x01, 0x00, 0x00, 0x00, // sec, usec
		0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // cap len, full len
		0x01, 0x02, 0x03, 0x04, // data
	}
	return bytes
}
