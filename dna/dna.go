package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DNA/scanner"
)

type Configuration struct {
	NetworkDeviceName   string
	RadisServerIP       string
	RadisServerPort     string
	RadisServerProtocol string
}

func main() {

	fmt.Println("\n-----------------------------------------------------------------")
	fmt.Println("|     Distributed Network Analysis (DNA) project                |")
	fmt.Println("|     Team-6:    Edward Verenich, Gennady Staskevich            |")
	fmt.Println("|---------------------------------------------------------------|")

	//read config file
	conf := read_config_file()
	redisURL := conf.RadisServerIP + ":" + conf.RadisServerPort

	scanner.Scan(conf.NetworkDeviceName, redisURL, conf.RadisServerProtocol)
	fmt.Println("--Done--")
}

func read_config_file() Configuration {
	fmt.Println("|---------------------------------------------------------------|")
	fmt.Println("|  [dna] Reading configuration file:  conf.jason                |")
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("Error opening configuration file:", err)
	}

	// //pring configuration
	// fmt.Println("|\tNetworkDeviceName:\t" + configuration.NetworkDeviceName)
	// fmt.Println("|\tRedis server IP:\t" + configuration.RadisServerIP)
	// fmt.Println("|\tRedis server port:\t" + configuration.RadisServerPort)
	// fmt.Println("|\tRedis server protocol:\t" + configuration.RadisServerProtocol)

	return configuration
}
