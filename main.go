package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func main() {

	r := mux.NewRouter()
	r.PathPrefix("/healthz").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		formatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.%07d",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond())
		w.Header().Set("Content-Type", "application/json")
		content := `{"status": "OK", "time": "` + formatted + "\"}"
		w.Write([]byte(content))
	})

	r.PathPrefix("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			log.Printf("Scheme: https. Server name: %s", r.TLS.ServerName)
		} else {
			log.Printf("Scheme: %s", "http")
		}
		log.Printf("Request:  %s%s", r.RemoteAddr, r.URL.Path)
		w.Write([]byte(r.RequestURI))
	})

	cert := os.Getenv("TLS_CERT")
	key := os.Getenv("TLS_KEY")
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = ":8080"
	} else {
		port = ":" + port
	}

	var err error
	if len(cert) > 0 && len(key) > 0 {
		log.Println("TLS enabled")
		log.Printf("The cert is at %s", cert)
		log.Printf("The key is at %s", key)

		cfg := &tls.Config{
			MinVersion:               tls.VersionTLS10,
			MaxVersion:               tls.VersionTLS13,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				// TLS 1.0 - 1.2 chipher suites
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

				// TLS 1.3 cipher suites.
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,

				// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
				// that the client is doing version fallback. See RFC 7507.
				tls.TLS_FALLBACK_SCSV,
			},
		}
		srv := &http.Server{
			Addr:         port,
			Handler:      r,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}

		err = srv.ListenAndServeTLS(cert, key)
	} else {
		log.Println("TLS disabled")
		err = http.ListenAndServe(port, r)
	}

	if err != nil {
		log.Fatal(err.Error())
	}
}
