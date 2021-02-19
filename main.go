package main

import (
	"net/http"
	"os"
	"log"

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

	var err error
	if len(cert) > 0 && len(key) > 0 {
		log.Println("TLS enabled")
		log.Printf("The cert is at %s", cert)
		log.Printf("The key is at %s", key)
		err = http.ListenAndServeTLS(":8080", cert, key, r)	
	} else {
		log.Println("TLS disabled")
		err = http.ListenAndServe(":8080", r)
	}

	if err != nil {
		log.Fatal(err.Error())
	}
}
