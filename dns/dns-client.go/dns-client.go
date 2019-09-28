// +build darwin/amd64
package main

import (
	"fmt"
	"net"
	"os"
)

const (
	port          = "53"
	destinationIP = "8.8.8.8"
	service       = destinationIP + ":" + port
)

// args for running dns-client are a domain name and record type (A or NS)

func main() {
	fmt.Println("service: ", service)
	if len(os.Args) != 3 {
		fmt.Errorf("Wrong number of args: domain name and record type needed")
		os.Exit(1)
	}

	domainName := os.Args[1]
	recordType := os.Args[2]
	fmt.Println("domain name: ", domainName)
	fmt.Println("query type: ", queryType)

	// create a socket
	udpAddr, err := net.ResolveUDPAddr("udp4", service)
	checkError(err)

	conn, err := net.DialUDP("udp4", nil, udpAddr)
	checkError(err)
	defer conn.Close()

	queryMsg := buildQuery(domainName, recordType)
	// write to the socket
	// _, err = conn.Write()
	// checkError(err)

	// read from socket
	// msg, err := conn.Read()
	// checkError(err)

	fmt.Println("Got to the end!")
}

func checkError(err error) {
	if err != nil {
		fmt.Errorf("Fatal error: %v", err.Error())
		os.Exit(1)
	}
}

type Header struct {
	identification int16
	flags          []byte
	qCount         int
	ansCount       int
	authCount      int
	addCount       int
}

type Question struct {
	name  string
	qType string
	class int
}

// write func to build message
func buildQuery(name string, record string) {
	return nil
}

// write func to encode message
func encode() {
	return nil
}

// write func to decode response message
