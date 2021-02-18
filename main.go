package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()
	r.PathPrefix("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RequestURI))
		return
	})

	cert := os.Getenv("TLS_CERT")
	key := os.Getenv("TLS_KEY")

	if len(cert) > 0 && len(key) > 0 {
		http.ListenAndServeTLS(":8443", cert, key, r)	
	} else {
		http.ListenAndServe(":8080", r)		
	}

}
