package main

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	goslog "golang.org/x/exp/slog"

	"github.com/gorilla/mux"
	"github.com/pathecho/auth"
)

var (
	Logger *goslog.Logger
	opts   goslog.HandlerOptions
)

func init() {
	doLog := os.Getenv("DOLOG")
	// TODO getting configuration parameters of the control,
	// then use these parameters to customize the logger.
	if doLog == "" {
		opts.Level = goslog.LevelError
	} else {
		opts.Level = goslog.LevelInfo
	}
	Logger = goslog.New(goslog.NewJSONHandler(os.Stdout, &opts))
	goslog.SetDefault(Logger)
}

func main() {

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
		Logger.Info("GET", "path", r.RequestURI)
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

	r.PathPrefix("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RequestURI))
		Logger.Info("GET", "path", r.RequestURI)
	})

	r.PathPrefix("/").Methods("POST").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		formatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.%07dZ",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond())

		var data []byte
		var err error
		defer r.Body.Close()
		Logger.Info("Accept-Encoding header", "value", r.Header.Get("Accept-Encoding"))
		if strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") {
			var reader *gzip.Reader
			reader, err = gzip.NewReader(r.Body)
			if err != nil {
				Logger.Error("Cannot create gzip reader", "Error", err.Error())
			} else {
				defer reader.Close()
				data, err = io.ReadAll(reader)
				if err != nil {
					Logger.Error("Cannot read from unzipped body", "Error", err.Error())
				}
			}
		} else {
			data, err = io.ReadAll(r.Body)
			if err != nil {
				Logger.Error("Cannot read from request body", "Error", err.Error())
			}
		}

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			content := `{"status":"Failed","time":"` + formatted + `"error":"` + err.Error() + `"}`
			w.Write([]byte(content))
		} else {
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			content := `{"status":"Created","time":"` + formatted + "\"}"
			w.Write([]byte(content))
			Logger.Info("POST", "path", r.RequestURI, "content", string(data))
		}
	})

	r.PathPrefix("/").Methods("PUT").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		formatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d.%07dZ",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond())
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		content := `{"status":"Modified","time":"` + formatted + "\"}"
		w.Write([]byte(content))

		data, err := io.ReadAll(r.Body)
		if err != nil {
			Logger.Error("Read put body", "Error", err.Error())
		}
		Logger.Info("PUT", "path", r.RequestURI, "content", string(data))
	})

	r.PathPrefix("/").Methods("DELETE").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		Logger.Info("DELETE", "path", r.RequestURI)
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
		Logger.Info("TLS enabled")
		Logger.Info("Certificate", "cert", cert)
		Logger.Info("Certificate", "key", key)

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
		Logger.Info("TLS disabled")
		err = http.ListenAndServe(port, r)
	}

	if err != nil {
		Logger.Error(err.Error())
	}
}
