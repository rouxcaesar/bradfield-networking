package main

import (
	"fmt"
	"log"
	"net/http"
)

const (
	host = "localhost"
	port = "8000"
)

func main() {
	fmt.Printf("Running on %v:%v\n", host, port)
	http.HandleFunc("/", handler) // each request calls handler

	// ListenAndServe starts an HTTP server with a given address and handler.
	// The handler is usually nil, which means to use DefaultServeMux.
	// ServeMux is an HTTP request multiplexer.
	// It matches the URL of each incoming request against a list of registered
	// patterns and calls the handler for the pattern that most closely matches the URL.
	log.Fatal(http.ListenAndServe(host+":"+port, nil))
}

// handler echoes the path component of the requested URL.
// ResponseWriter is an interface used by an HTTP handler to
// construct an HTTP response.
// Request is a type that represents an HTTP request received by a server or to be sent by a client.
func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("request: %v\n", r)
	//	fmt.Fprintf(w, "URL.Path = %q\n", r.URL.Path)
	//	fmt.Fprintf(w, "Request Method = %v\n", r.Method)
	//	fmt.Fprintf(w, "Request ContentLength = %v\n", r.ContentLength)
	//
	//	for k, v := range r.Header {
	//		fmt.Fprintf(w, "Request Header %v = %v\n", k, v)
	//	}
}
