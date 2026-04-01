package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"os/signal"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
)

func main() {
	var config mockidp.Config
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] '<mockidp.Config json string>'\n", os.Args[0])
		os.Exit(1)
	}
	if err := json.Unmarshal([]byte(flag.Arg(0)), &config); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	idp := mockidp.New(config)
	r := mux.NewRouter()
	idp.Register(r)
	server := httptest.NewServer(r)

	fmt.Printf("Server listening on %s\n", server.Listener.Addr())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	server.Close()
}
