package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/pathecho/auth"
)

func main() {
	doLog := os.Getenv("DOLOG")

	r := mux.NewRouter()
	r.PathPrefix("/healthz").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		formatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.%07dZ",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond())
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		content := `{"status":"OK","time":"` + formatted + "\"}"
		w.Write([]byte(content))
	})

	r.PathPrefix("/post/").Methods("POST").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		formatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.%07dZ",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond())
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		content := `{"status":"Created","time":"` + formatted + "\"}"
		w.Write([]byte(content))
	})

	r.PathPrefix("/version").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := os.Getenv("version")
		w.Header().Set("Content-Type", "application/json")
		content := `{"status":"FAIL"}`
		resp, err := http.Get(target)
		if err != nil || resp.StatusCode != 200 {
			w.Write([]byte(content))
			return
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			w.Write([]byte(content))
			return
		}
		w.Write(data)
	})

	// If this is to setup to deal with protected resources
	// For protected resouces
	if auth.IsSecurityEnabled() {
		secured := r.PathPrefix("/secured").Subrouter()
		authenticator := auth.New()
		secured.Use(authenticator.Middleware())
		// regardless what method call, always write the request uri back
		// to the body
		secured.Path("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(r.RequestURI))
		})

		r.Path("/api/callback").Methods("GET").HandlerFunc(authenticator.APICallback)
	}

	r.PathPrefix("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if doLog == "True" {
			if r.TLS != nil {
				log.Printf("Scheme: https. Server name: %s", r.TLS.ServerName)
			} else {
				log.Printf("Scheme: %s", "http")
			}
			log.Printf("Request:  %s%s", r.RemoteAddr, r.URL.Path)
		}
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
