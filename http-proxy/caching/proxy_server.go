package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	host = "localhost"
	port = "7000"
)

func main() {
	fmt.Printf("Running on %v:%v\n", host, port)

	http.HandleFunc("/", forwardToServer)
	http.ListenAndServe(host+":"+port, nil)
}

func forwardToServer(w http.ResponseWriter, r *http.Request) {
	proxyReq, err := http.NewRequest("GET", "http://localhost:9000/", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for header, values := range r.Header {
		for _, value := range values {
			fmt.Printf("header value: %v \n\n", value)
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

	w.Write(body)
}
