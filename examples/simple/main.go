package main

import (
	"log"
	"net/http"

	"github.com/foomo/simplecert"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	log.Fatal(simplecert.ListenAndServeTLSLocal(":443", nil, "myawesomewebsite.com"))
}
