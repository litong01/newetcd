package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	goslog "log/slog"

	"github.com/gorilla/mux"
	"github.com/itchyny/gojq"
)

var (
	Logger *goslog.Logger
	opts   goslog.HandlerOptions
)

var (
	storeFile = "store.json"
	mu        sync.Mutex
)

func loadStore() (map[string]interface{}, error) {
	file, err := os.Open(storeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]interface{}), nil
		}
		return nil, err
	}
	defer file.Close()

	var store map[string]interface{}
	err = json.NewDecoder(file).Decode(&store)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func saveStore(store map[string]interface{}) error {
	file, err := os.Create(storeFile)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(store)
}

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

	r.PathPrefix("/").Methods("PUT").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		value := r.URL.Query().Get("value")

		mu.Lock()
		defer mu.Unlock()

		store, err := loadStore()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		query, err := gojq.Parse(fmt.Sprintf(".%s = \"%s\"", key, value))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		code, err := gojq.Compile(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		iter := code.Run(store)
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if err, ok := v.(error); ok {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			store = v.(map[string]interface{})
		}

		err = saveStore(store)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Put key=%s value=%s\n", key, value)
	})

	r.PathPrefix("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")

		mu.Lock()
		defer mu.Unlock()

		store, err := loadStore()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		query, err := gojq.Parse(fmt.Sprintf(".%s", key))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		code, err := gojq.Compile(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		iter := code.Run(store)
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if err, ok := v.(error); ok {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "%s\n", v)
		}
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
