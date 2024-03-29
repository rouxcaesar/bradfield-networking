package main

import (
	"fmt"
	"log"
	"net/http"
)

const (
	host = "localhost"
	port = "7000"
)

func main() {
	fmt.Printf("Running on %v:%v\n", host, port)
	http.HandleFunc("/", handleRequestAndRedirect)
	//http.RedirectHandler("localhost:8000", 200)
	log.Fatal(http.ListenAndServe(host+":"+port, nil))
}

func handleRequestAndRedirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL
	url.Host = "localhost:8000"
	url.Scheme = "http"

	proxyReq, err := http.NewRequest(r.Method, url.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxyReq.Header.Set("Host", r.Host)
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)

	proxyReq.Header = r.Header
	//for header, values := range r.Header {
	//	for _, value := range values {
	//		proxyReq.Header.Add(header, value)
	//	}
	//}

	client := &http.Client{}
	client.Do(proxyReq)
}
