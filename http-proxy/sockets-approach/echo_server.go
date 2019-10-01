package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func main() {
	host, port, err := getArgs()
	if err != nil {
		fmt.Printf("failed to run: %v\n", err)
		return
	}
	fmt.Printf("Server listening on %v:%v\n", host, port)

	intPort, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println("failed to convert port string into an in")
	}

	// Create a socket and get it's file descriptor.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		fmt.Println("failed to create a socket")
		return
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrInet4{
		Port: intPort,
	}

	// Bind the file descriptor to a port number.
	err = unix.Bind(fd, addr)
	if err != nil {
		fmt.Printf("failed to bind to addr %v on port %v\n", addr.Addr, addr.Port)
		return
	}

	// Have the file descriptor listen on the port for any
	// incoming connections.
	// The second arg is int backlog.
	// This is the number of connections allowed on the incoming queue.
	err = unix.Listen(fd, 1)
	if err != nil {
		fmt.Printf("failed to listen to addr %v on port %v\n", addr.Addr, addr.Port)
		return
	}

	requestfd, saddr, err := unix.Accept(fd)
	if err != nil {
		fmt.Printf("accept failed: %v\n", err)
	}

	handler(requestfd, saddr)
}

func getArgs() (string, string, error) {
	if len(os.Args) != 3 {
		return "", "", errors.New("need to specify the host and port")
	}

	host := os.Args[1]
	port := os.Args[2]

	return host, port, nil
}

func handler(requestfd int, saddr unix.Sockaddr) {
	defer unix.Close(requestfd)

	fmt.Println("Got your request!")
	// Get request message
	//requestMsg := make([]byte, 4096)
}
