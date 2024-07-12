package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run subnet_calculator.go <IP address> <Subnet mask>")
		os.Exit(1)
	}

	ip := os.Args[1]
	subnetMask := os.Args[2]

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		fmt.Println("Invalid IP address")
		os.Exit(1)
	}

	_, subnet, err := net.ParseCIDR(ip + "/" + subnetMask)
	if err != nil {
		fmt.Println("Invalid subnet mask:", err)
		os.Exit(1)
	}

	network := subnet.IP
	broadcast := calculateBroadcastAddress(network, subnet.Mask)
	firstIP, lastIP := calculateFirstLastIP(network, broadcast)

	fmt.Println("Network Address:", network)
	fmt.Println("Broadcast Address:", broadcast)
	fmt.Println("First Valid IP:", firstIP)
	fmt.Println("Last Valid IP:", lastIP)
}

func calculateBroadcastAddress(network net.IP, subnetMask net.IPMask) net.IP {
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | (^subnetMask[i])
	}
	return broadcast
}

func calculateFirstLastIP(network, broadcast net.IP) (firstIP, lastIP net.IP) {
	firstIP = make(net.IP, len(network))
	lastIP = make(net.IP, len(network))

	copy(firstIP, network)
	copy(lastIP, broadcast)

	// Increment the last octet of firstIP for the first valid host
	firstIP[3]++

	// Decrement the last octet of lastIP for the last valid host
	lastIP[3]--

	return firstIP, lastIP
}
