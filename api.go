// Implements the SQRL server-side protocol (SSP). The SqrlSspApi
// is a stateful server object that manages SQRL identities. The /cli.sqrl
// exposed at Cli is the only endpoint that is required to operate in
// conjunction with the SQRL client. This endpoint is required to be served
// over https.
//
// While it's possible that this code can be run within a web server that
// terminates TLS itself, the expectation is that it is served from behind
// a load balancer or reverse proxy. While I attempt to reconstruct the
// host and paths from the request and standard forwarding headers, this
// can be unreliable and it's best to confgure the HostOverride and RootPath
package ssp

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Nut is a cryptographic nonce used by SQRL
type Nut string

// Sqrl64 is a shortcut base64.RawURLEncoding encoding which is used
// pervasively throughout the SQRL protocol
var Sqrl64 = base64.RawURLEncoding

// SqrlScheme is sqrl
const SqrlScheme = "sqrl"

// A Tree produces Nuts :)
type Tree interface {
	Nut() (Nut, error)
}

// ErrNotFound specific error returned if a Hoard
// or identity isn't found. This is to differentiate
// from more serious errors at the storage level
var ErrNotFound = fmt.Errorf("Not Found")

// Hoard stores Nuts for later use
type Hoard interface {
	Get(nut Nut) (*HoardCache, error)
	GetAndDelete(nut Nut) (*HoardCache, error)
	Save(nut Nut, value *HoardCache, expiration time.Duration) error
}

// HoardCache is the state associated with a Nut
type HoardCache struct {
	State        string
	RemoteIP     string
	OriginalNut  Nut
	PagNut       Nut
	LastRequest  *CliRequest
	LastResponse []byte
}

// PagHandler a function that generates a URL to be returned to
// once auth has succeeded
type PagHandler func(identity string) string

// Authenticator interface to allow user management triggered by
// SQRL authentication events.
type Authenticator interface {
	// Called when a SQRL identity has been successfully authenticated. It
	// should return a URL that will finish authentication to create a
	// logged in session. This is also called for a new user.
	// If an error occurs this should return an error
	// page redirection
	AuthenticateIdentity(identity string) string
	// When an identity is rekeyed, it's necessary to swap the identity
	// associated with a given user. This callback happens when a user
	// wishes to swap their previous identity for a new one.
	SwapIdentities(previousIdentity, newIdentity string) error
}

// SqrlSspAPI implements the endpoitns outlined here
// https://www.grc.com/sqrl/sspapi.htm
type SqrlSspAPI struct {
	tree          Tree
	hoard         Hoard
	NutExpiration time.Duration
	Authenticated *sync.Map
	// set to the hostname for serving SQRL urls; this can include a port if necessary
	HostOverride string
	// if the SQRL endpoints are not at the root of the host, then this overrides the path where they are hosted
	RootPath      string
	Authenticator Authenticator
}

// NewSqrlSspAPI needs a Tree implementation that produces Nuts
// Also needs a Hoard to store a retrieve Nuts
func NewSqrlSspAPI(tree Tree, hoard Hoard) *SqrlSspAPI {
	return &SqrlSspAPI{
		tree:          tree,
		hoard:         hoard,
		NutExpiration: 10 * time.Minute,
		Authenticated: &sync.Map{},
	}
}

// Host gets the host in order of preference:
// SqrlSspAPI.HostOverride, header X-Forwarded-Host, Request.Host
func (api *SqrlSspAPI) Host(r *http.Request) string {
	host := api.HostOverride
	if host == "" {
		host = r.Header.Get("X-Forwarded-Host")
	}
	if host == "" {
		host = r.Header.Get("X-Forwarded-Server")
	}
	if host == "" {
		host = r.Host
	}
	return host
}

func (api *SqrlSspAPI) findIdentity(idk string) (*SqrlIdentity, error) {
	if knownUser, ok := api.Authenticated.Load(idk); ok {
		log.Printf("Found existing identity: %#v", knownUser)
		if identity, ok := knownUser.(*SqrlIdentity); ok {
			return identity, nil
		}
		return nil, fmt.Errorf("Wrong type for identity %t", knownUser)
	}
	return nil, ErrNotFound
}

func (api *SqrlSspAPI) swapIdentities(previousIdentity, newIdentity *SqrlIdentity) error {
	err := api.Authenticator.SwapIdentities(previousIdentity.Idk, newIdentity.Idk)
	if err != nil {
		return err
	}
	api.Authenticated.Delete(previousIdentity.Idk)
	return nil
}

// HTTPSRoot returns the best guess at the https root URL for this server
func (api *SqrlSspAPI) HTTPSRoot(r *http.Request) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   api.Host(r),
		Path:   api.RootPath,
	}
}

// RemoteIP gets the remote IP as a string from a request
// It prefers the X-Forwarded-For header since it's likely
// this server will be behind a load balancer
func (api *SqrlSspAPI) RemoteIP(r *http.Request) string {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	return ipAddress
}

func (api *SqrlSspAPI) qry(nut Nut) string {
	return fmt.Sprintf("%v/cli.sqrl?nut=%v", api.RootPath, nut)
}
