package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	host       = "localhost"
	port       = "7000"
	serverPort = "9000"
)

var cache = make(map[string][]byte)

func main() {
	fmt.Printf("Running on %v:%v\n", host, port)

	http.HandleFunc("/", forwardToServer)
	http.ListenAndServe(host+":"+port, nil)
}

func forwardToServer(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	fmt.Println("Path: ", path)

	// First we chech our cache.
	// If we have the response cached, we return it.
	if _, ok := cache[path]; ok {
		fmt.Println("retrieving from cache")
		w.Write(cache[path])
		return
	}

	// If the response is not cached, then we forward to our server.
	url := "http://" + host + ":" + serverPort + "/"

	proxyReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for header, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(header, value)
		}
	}

	client := &http.Client{}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(body))

	// Store our response in our cache for future requests for the same resource.
	cache[path] = body
	fmt.Println("saved to cache")

	w.Write(body)
}
