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

	//Will be used by faster packet decoder (these will be reused)
	//ethLayer layers.Ethernet
	//ipLayer  layers.IPv4
	//tcpLayer layers.TCP
)

//"wireless network device name on mac: "en1",  "eth0" for physical connection
func Scan(network_Device_Name string, redis_Server_URL string, redis_Protocol string) {

	networkDeviceName = network_Device_Name
	redisServerURL = redis_Server_URL
	redisProtocol = redis_Protocol

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
	var filter string = "tcp"
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

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		register_network_call_with_redis(ip.Protocol, ip.DstIP)
	}

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
