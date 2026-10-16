// Command web is a tiny HTTP server for the end-to-end tests. It answers
// every request with its name and the port it was reached on.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	name := flag.String("name", "web", "name returned in responses")
	ports := flag.String("ports", "8080,2222", "comma-separated ports to listen on")
	flag.Parse()

	errCh := make(chan error, 4)
	for _, port := range strings.Split(*ports, ",") {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "hello from %s on port %s\n", *name, port)
		})
		// /slow keeps a connection open for several seconds
		mux.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) {
			for i := 1; i <= 8; i++ {
				fmt.Fprintf(w, "tick %d\n", i)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				time.Sleep(time.Second)
			}
		})
		go func() { errCh <- http.ListenAndServe(":"+port, mux) }()
	}
	log.Fatal(<-errCh)
}
