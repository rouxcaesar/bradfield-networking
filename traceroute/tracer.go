package main

import (
	"fmt"
	"log"
	"net"
	"os"

	//	"syscall"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func main() {
	var err error
	//	target := parseArgs()
	//	if target == "" {
	//		os.Exit(1)
	//	}

	//	ping()
	//}
	//
	//func ping() {
	// Send packet.
	fd, _ := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	//	defer unix.Close(fd)
	//
	addr := unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{8, 8, 8, 8}, //172.217.10.46
	}

	packet := createPacket()
	err = unix.Sendto(fd, packet, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
	fmt.Println("Packet sent")
	//	if err := unix.Connect(fd, addr); err != nil {
	//		fmt.Printf("Error: %v\n", err.Error())
	//		return
	//	}
	//	if err := unix.Sendto(fd, data, 0, addr); err != nil {
	//		fmt.Printf("Error: %v\n", err.Error())
	//		return
	//	}

	// Receive response.
	rfd, _ := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	file := os.NewFile(uintptr(rfd), fmt.Sprintf("rfd %d", rfd))

	for {
		fmt.Println("Receiving packet")
		buffer := make([]byte, 1024)
		numRead, err := file.Read(buffer)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%X\n", buffer[:numRead])
	}
	//res := make([]byte, 1500)
	//if _, _, err := unix.Recvfrom(fd, res, unix.MSG_WAITALL); err != nil {
	//	fmt.Printf("Error: %v\n", err.Error())
	//	return
	//}

	//fmt.Printf("res: %v\n", res)
}

func createPacket() []byte {
	header := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 30,
		TTL:      64,
		Protocol: 1,
		Dst:      net.IPv4(8, 8, 8, 8), //172.217.10.46

	}

	icmp := []byte{
		8,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0xC0,
		0xDE,
	}

	checksum := csum(icmp)
	icmp[2] = byte(checksum)
	icmp[3] = byte(checksum >> 8)

	out, err := header.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return append(out, icmp...)
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}

	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}

func parseArgs() string {
	if len(os.Args) != 2 {
		fmt.Println("incorrect usage: tracer.go [target]")
		return ""
	}
	fmt.Println("Correct usage")
	return os.Args[1]
}
