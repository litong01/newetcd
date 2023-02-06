package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

type ApiResponse struct {
	Code    int32    `json:"code"`
	Type    string   `json:"type"`
	Message string   `json:"message,omitempty"`
	Keys    []string `json:"keys,omitempty"`
}

// Auth http handler
type Auth struct {
	Ctx          context.Context
	Oauth2config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	State        string
}

func IsSecurityEnabled() bool {
	if len(os.Getenv("issuer")) > 0 {
		return true
	}
	return false
}

// New create a new auth handler
func New() *Auth {
	issuer := os.Getenv("issuer")
	ctx := context.Background()

	var provider *oidc.Provider
	var err error
	for {
		provider, err = oidc.NewProvider(ctx, issuer)
		if err == nil {
			break
		}
		log.Println("Access keycloak errored out.")
		log.Println(err.Error())
		time.Sleep(3 * time.Second)
	}
	log.Println("OIDC provider created!")

	clientID := os.Getenv("client_id")
	clientSecret := os.Getenv("client_secret")
	redirectURL := os.Getenv("redirect_url")
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: oauth2.Endpoint{
			// From keycloak well-known/openid-configuration document, the authorization_endpoint
			AuthURL: os.Getenv("authURL"),
			// From keycloak well-known/openid-configuration document, the token_endpoint
			TokenURL: os.Getenv("tokenURL"),
		},
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.Println("OAuth2Config created!")

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	a := &Auth{
		ctx, oauth2Config, verifier, "JUSTASTRINGATTHEMOMENT",
	}
	return a
}

func (a *Auth) verifyState(r *http.Request) bool {
	state := r.URL.Query().Get("state")
	if state != a.State {
		log.Println("State cannot be verified")
		return false
	}
	log.Println("State was verified")
	return true
}

// APICallback callback handler to set access token for a request
// this method gets called by a redirect after a user is authenticated
// by the authenticator, so that the user token can be exchanged for
// access token.
func (a *Auth) APICallback(w http.ResponseWriter, r *http.Request) {
	// Verify the state
	if a.verifyState(r) == false {
		http.Error(w, "State can not be verified or missing", http.StatusBadRequest)
		return
	}

	// Exchange user authorization code for a access token.
	oauth2Token, err := a.Oauth2config.Exchange(a.Ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := a.Verifier.Verify(a.Ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)

	// Everything is good, should redirect user back to the
	// original request. The question is how to get the original url
	// probably can be saved before the authentication.
	// http.Redirect(w, r, "original url", http.StatusFound)
}

// GetEndpoint Create endpoint with state for user to start authentication process
func (a *Auth) GetEndpoint(w http.ResponseWriter, r *http.Request) {
	var resBody ApiResponse
	endpoint := a.Oauth2config.AuthCodeURL(a.State)

	w.Header().Add("X-Location", base64.StdEncoding.EncodeToString([]byte(endpoint)))
	resBody.Code = 0
	resBody.Type = "USER_LOGINENDPOINT_QUERY"
	resBody.Message = "SUCCESS"
	json.NewEncoder(w).Encode(resBody)
}

// Middleware  check security of a request
func (a *Auth) Middleware() mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("Entering the Auth middle ware")
			rawAccessToken := r.Header.Get("Authorization")
			if rawAccessToken == "" {
				log.Println("No access token, redirect to keycloak")
				http.Redirect(w, r,
					a.Oauth2config.AuthCodeURL(a.State),
					http.StatusFound)
				return
			}

			parts := strings.Split(rawAccessToken, " ")
			//Invalid or tampered access token, return bad request
			if len(parts) != 2 {
				w.WriteHeader(400)
				return
			}
			_, err := a.Verifier.Verify(a.Ctx, parts[1])
			// Token can not be verified, return for reauthenticate
			if err != nil {
				log.Println("Access token verification failed.")
				log.Println(err.Error())
				http.Redirect(w, r,
					a.Oauth2config.AuthCodeURL(a.State),
					http.StatusFound)
				return
			}
			log.Println("Access token verified successfully.")

			//Access token is now verified, moving on to the next handler
			h.ServeHTTP(w, r)
			log.Println("Exiting the Auth middle ware")
		})
	}
}
