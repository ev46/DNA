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
	local_ip_list []net.IP
	//local setting from config file
	networkDeviceName string

	//Redis specific
	client                     *redis.Client
	redisServerURL             string
	redisProtocol              string
	redisConnectionInitialized bool = false

	//snifing localhost specific
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle

	//Will be used by faster packet decoder (will reuse them)
	//ethLayer layers.Ethernet
	//ipLayer  layers.IPv4
	//tcpLayer layers.TCP
)

//"wireless network device name on mac: "en1",  "eth0" for physical connection
func Scan(network_Device_Name string, redis_Server_URL string, redis_Protocol string) {

	networkDeviceName = network_Device_Name
	redisServerURL = redis_Server_URL
	redisProtocol = redis_Protocol

	initialize_local_ip_list()

	initialize_redis_connection()

	Read_RAW_Socket_Data()

	// defer close
	defer client.Close()
	fmt.Println("\ndone...")
}

//----- PCAP read from
func Read_RAW_Socket_Data() {
	fmt.Println("|---------------------------------------------------------------|")
	fmt.Println("|  [scanner] Opening Device (PROMISCUOUS_MODE): " + networkDeviceName + "\t\t|")

	// Open device
	handle, err = pcap.OpenLive(networkDeviceName, snapshot_len, promiscuous, timeout)
	if err != nil {
		fmt.Println("| ----------------=============================-----------------|")
		fmt.Println("| Looks like there is an error getting live network stream. Try |")
		fmt.Println("| running it again with 'sudo' command                          |")
		fmt.Println("| ----------------=============================-----------------|")
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "tcp and port 80"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing TCP port 80 packets.")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		process_gopacket(packet)
	}
}

//------ PCAP Print PCAP Data -----
func process_gopacket(packet gopacket.Packet) {

	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer != nil {
	// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	// 	fmt.Printf("Ethernet layer | Type: %s | Src_MAC: %s Dst_MAC: %s\n", ethernetPacket.EthernetType, ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	// 	// Ethernet type is typically IPv4 but could be ARP or other
	// }

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		// fmt.Println("\nLayer Info: " + ip.Protocol.LayerType().String() == "ICMPv4")

		register_network_call_with_redis(ip.Protocol, ip.DstIP)
	}

	// // Let's see if the packet is TCP
	// tcpLayer := packet.Layer(layers.LayerTypeTCP)
	// if tcpLayer != nil {
	// 	tcp, _ := tcpLayer.(*layers.TCP)
	// 	fmt.Printf("\tTCP | From port %d to %d", tcp.SrcPort, tcp.DstPort)
	// 	fmt.Println("| TCP Seq: ", tcp.Seq)

	// 	// TCP layer variables:
	// 	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
	// 	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	// }

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

//Call redis from here (running redis on local host right now)
func register_network_call_with_redis(protocolType layers.IPProtocol, dst_ip net.IP) {

	if redisConnectionInitialized == true {
		foo := client.Cmd("ZINCRBY", "popularity", "1", dst_ip.String())
		if foo.Err != nil {
			fmt.Println(foo.Err.Error())
		} else {
			fmt.Printf("\tIPv4:%s\tDest: %s \n", protocolType, dst_ip)
		}
	}
}

//------------- Connection Pool for redis
func initialize_redis_connection() {
	//connect to redis server
	fmt.Println("|---------------------------------------------------------------|")
	fmt.Println("|  [scanner]\tInitializing Redis Client Configuration\t\t|")

	client, err = redis.Dial(redisProtocol, redisServerURL)

	if err != nil {
		fmt.Println("| WARNING: Problem connecting to Redis Server: " + redisServerURL + "\t\t|")
		fmt.Println("|      " + err.Error() + "\t|")
		fmt.Println("|  \tPACKET_LOGGING_MODE: PRINT_TO_SCREEN\t\t\t|")
		fmt.Println("|---------------------------------------------------------------|")
	} else {
		fmt.Println("|\t\tConnected to Redis Server: " + redisServerURL + "|" + redisProtocol + "\t|")
		fmt.Println("|\t\tPACKET_LOGGING_MODE: SEND_TO_REDIS  \t\t|")
		fmt.Println("|---------------------------------------------------------------|")
		redisConnectionInitialized = true
	}
}

func initialize_local_ip_list() {
	ifaces, err := net.Interfaces()

	//handle err
	if err == nil {
		for _, i := range ifaces {
			addrs, err := i.Addrs()

			//handle err
			if err == nil {
				for _, addr := range addrs {

					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}

					if ip.IsGlobalUnicast() {
						local_ip_list = append(local_ip_list, ip)
					}
				}
			} else { //handle error
				fmt.Println(err)
			}
		}
	} else { //handle error
		fmt.Println(err)
	}
}

/** CODE IN PROGRESS

//---------- Call redis (removes local duplicates as destination addresses)
func register_network_call_with_redis(protocolType layers.IPProtocol, dst_ip net.IP) {

	for i := 0; i < len(local_ip_list); i++ {
		if local_ip_list[i].Equal(dst_ip) {
			fmt.Println("\n\t---Detected Local IP:", dst_ip)
		} else {
			if redisConnectionInitialized == true {

				foo := client.Cmd("ZINCRBY", "popularity", "1", dst_ip)
				if foo.Err != nil {
					fmt.Println(foo.Err.Error())
				}
			} else { //just print to screen
				fmt.Printf("\n\tDst: %s\t Type: %s", dst_ip, protocolType.LayerType().String())
			}
		}
	}
}

//---------- fast packet decoder
func process_gopacket_fast_decoder(packet gopacket.Packet) {
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&tcpLayer,
	)
	foundLayerTypes := []gopacket.LayerType{}

	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	if err != nil {
		fmt.Println("Trouble decoding layers: ", err)
	}

	for _, layerType := range foundLayerTypes {
		if layerType == layers.LayerTypeIPv4 {
			fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
		}
		if layerType == layers.LayerTypeTCP {
			fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
			fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
		}
	}
}
code in progress */

/** TEST CODE
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

*/
