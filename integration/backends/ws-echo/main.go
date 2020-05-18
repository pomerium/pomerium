package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

func main() {
	var (
		certFile, keyFile, bindAddr string
	)

	flag.StringVar(&certFile, "cert-file", "", "the tls cert file to use")
	flag.StringVar(&keyFile, "key-file", "", "the tls key file to use")
	flag.StringVar(&bindAddr, "bind-addr", "", "the address to listen on")
	flag.Parse()

	var err error
	if certFile != "" && keyFile != "" {
		if bindAddr == "" {
			bindAddr = ":5443"
		}
		fmt.Println("starting server on", bindAddr)
		err = http.ListenAndServeTLS(bindAddr, certFile, keyFile, http.HandlerFunc(handle))
	} else {
		if bindAddr == "" {
			bindAddr = ":5080"
		}
		fmt.Println("starting server on", bindAddr)
		err = http.ListenAndServe(bindAddr, http.HandlerFunc(handle))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen and serve: %v\n", err)
		os.Exit(1)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	conn, err := (&websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}).Upgrade(w, r, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error upgrading websocket connection: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	for {
		mt, p, err := conn.ReadMessage()
		if err != nil {
			return
		}

		err = conn.WriteMessage(mt, p)
		if err != nil {
			return
		}
	}
}
