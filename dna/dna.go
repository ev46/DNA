package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Configuration struct {
	NetworkDeviceName string
	RadisServerIP     string
}

func main() {
	read_config_file()

	// fmt.Println("\n Starting the DNA scanner...(gennady1, ev46)")
	// scanner.Scan()
	// fmt.Println("--Done--")
}

func read_config_file() {
	fmt.Println("\n Reading configuration file (conf.jason) ")
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	configuration := Configuration{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("Error opening configuration file:", err)
	}
	fmt.Println("\tNetworkDeviceName:\t" + configuration.NetworkDeviceName)
	fmt.Println("\tRadis Server IP:\t" + configuration.RadisServerIP)
	// fmt.Println("Protocol: " + configuration.Protocol)
}
