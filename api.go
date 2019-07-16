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

var Sqrl64 = base64.RawURLEncoding

const SqrlScheme = "sqrl"

// A Tree produces Nuts :)
type Tree interface {
	Nut(payload interface{}) (Nut, error)
}

var NotFoundError = fmt.Errorf("Not Found")

// Hoard stores Nuts for later use
type Hoard interface {
	Get(nut Nut) (interface{}, error)
	GetAndDelete(nut Nut) (interface{}, error)
	Save(nut Nut, value interface{}, expiration time.Duration) error
}

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

// SqrlSspAPI implements the endpoitns outlined here
// https://www.grc.com/sqrl/sspapi.htm
type SqrlSspAPI struct {
	tree          Tree
	hoard         Hoard
	NutExpiration time.Duration
	Authenticated *sync.Map
	HostOverride  string
	RootPath      string
	PagHandler    PagHandler
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

func (api *SqrlSspAPI) FindIdentity(idk string) (*SqrlIdentity, error) {
	if knownUser, ok := api.Authenticated.Load(idk); ok {
		log.Printf("Found existing identity: %#v", knownUser)
		if identity, ok := knownUser.(*SqrlIdentity); ok {
			return identity, nil
		} else {
			return nil, fmt.Errorf("Wrong type for identity %t", knownUser)
		}
	}
	return nil, NotFoundError
}

func (api *SqrlSspAPI) SwapIdentities(previousIdentity, newIdentity *SqrlIdentity) error {
	api.Authenticated.Delete(previousIdentity.Idk)
	// TODO some callback to broadcast that this happened
	return nil
}

func (api *SqrlSspAPI) HttpsRoot(r *http.Request) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   api.Host(r),
		Path:   api.RootPath,
	}
}

func (api *SqrlSspAPI) RemoteIP(r *http.Request) string {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	return ipAddress
}

func (api *SqrlSspAPI) Qry(nut Nut) string {
	return fmt.Sprintf("%v/cli.sqrl?nut=%v", api.RootPath, nut)
}
