package ssp

import (
	"log"
	"net/http"

	"github.com/davecgh/go-spew/spew"
)

// Cli implements the /cli.sqrl endpoint
func (api *SqrlSspAPI) Cli(w http.ResponseWriter, r *http.Request) {
	log.Printf("Req: %v", r.URL)
	nut := Nut(r.URL.Query().Get("nut"))
	if nut == "" {
		w.Write(NewCliResponse("", "").WithClientFailure().Encode())
		return
	}

	// TODO remove me
	for k, v := range r.Header {
		log.Printf("%v: %v", k, v)
	}

	response := NewCliResponse(Nut(nut), "")
	req, err := ParseCliRequest(r)
	if err != nil {
		log.Printf("Can't parse body or bad signature: %v", err)
		w.Write(response.WithClientFailure().Encode())
		return
	}
	// Signature is OK from here on!

	// TODO remove me
	spew.Dump(req)

	hoardCache, err := api.getAndDelete(Nut(nut))
	if err != nil {
		if err == ErrNotFound {
			log.Printf("Nut %v not found", nut)
			w.Write(response.WithClientFailure().WithCommandFailed().Encode())
			return
		}
		log.Printf("Failed nut lookup: %v", err)
		w.Write(response.WithTransientError().WithCommandFailed().Encode())
		return
	}

	// validate last response against this request
	if hoardCache.LastResponse != nil && !req.ValidateLastResponse(hoardCache.LastResponse) {
		w.Write(response.WithCommandFailed().Encode())
		// this is intentionally after so nothing about last response leaks
		log.Printf("Last response %v and this one don't match: %v", string(hoardCache.LastResponse), string(req.Server))
		return
	}

	// validate the IP if required
	if hoardCache.RemoteIP != api.RemoteIP(r) {
		if !req.Client.Opt["noiptest"] {
			log.Printf("Rejecting on IP mis-match orig: %v current: %v", hoardCache.RemoteIP, api.RemoteIP(r))
			w.Write(response.WithCommandFailed().Encode())
			return
		}
	} else {
		log.Printf("Matched IP addresses")
		response = response.WithIPMatch()
	}

	// validating the current request and associated Idk's match
	if hoardCache.LastResponse != nil && hoardCache.LastRequest.Client.Idk != req.Client.Idk {
		log.Printf("Identity mismatch orig: %v current %v", hoardCache.LastRequest.Client.Idk, req.Client.Idk)
		w.Write(response.WithCommandFailed().WithClientFailure().WithBadIDAssociation().Encode())
		return
	}

	// generate new nut
	nut, err = api.tree.Nut()
	if err != nil {
		log.Printf("Error generating nut: %v", err)
		w.Write(response.WithTransientError().Encode())
		return
	}

	response.Nut = nut
	response.Qry = api.qry(nut)

	// check if the same user has already been authenticated previously
	accountDisabled := false
	identity, err := api.authStore.FindIdentity(req.Client.Idk)
	if err != nil && err != ErrNotFound {
		log.Printf("Error looking up identity: %v", err)
		w.Write(response.WithTransientError().Encode())
		return
	}

	var previousIdentity *SqrlIdentity
	if req.Client.Pidk != "" {
		previousIdentity, err = api.authStore.FindIdentity(req.Client.Pidk)
		if err != nil && err != ErrNotFound {
			log.Printf("Error looking up previous identity: %v", err)
			w.Write(response.WithTransientError().Encode())
			return
		}
	}
	if previousIdentity != nil {
		response.WithPreviousIDMatch()
	}

	if identity != nil {
		accountDisabled = identity.Disabled
		response.WithIDMatch()
		if req.Client.Opt["suk"] {
			response.Suk = identity.Suk
		}
		if req.Client.Cmd == "enable" || req.Client.Cmd == "remove" {
			err := req.VerifyUrs(identity.Vuk)
			if err != nil {
				log.Printf("enable command failed urs validation")
				if identity.Disabled {
					response.WithSQRLDisabled()
				}
				w.Write(response.WithClientFailure().WithCommandFailed().Encode())
				return
			}
			if req.Client.Cmd == "enable" {
				log.Printf("Reenabled account: %v", identity.Idk)
				identity.Disabled = false
				err := api.authStore.SaveIdentity(identity)
				if err != nil {
					log.Printf("Failed saving identity %v: %v", identity.Idk, err)
					w.Write(response.WithClientFailure().WithCommandFailed().Encode())
					return
				}
			} else if req.Client.Cmd == "remove" {
				err := api.removeIdentity(identity)
				if err != nil {
					log.Printf("Failed removing identity %v: %v", identity.Idk, err)
					w.Write(response.WithClientFailure().WithCommandFailed().Encode())
					return
				}
				log.Printf("removed identity %v", identity.Idk)
			}
		}
		if req.Client.Cmd == "disable" {
			identity.Disabled = true
			err := api.authStore.SaveIdentity(identity)
			if err != nil {
				log.Printf("Failed saving identity %v: %v", identity.Idk, err)
				w.Write(response.WithClientFailure().WithCommandFailed().Encode())
				return
			}
		}

		if identity.Disabled {
			response.WithSQRLDisabled()
		}
	} else if req.Client.Cmd == "ident" {
		// create new identity from the request
		identity = req.Identity()
		// handle previous identity swap if the current identity is new
		if previousIdentity != nil {
			log.Printf("Swapped identity %v for %v", previousIdentity, identity)
			err := api.swapIdentities(previousIdentity, identity)
			if err != nil {
				log.Printf("Failed swapping identities: %v", err)
				w.Write(response.WithTransientError().WithCommandFailed().Encode())
				return
			}
			// TODO should we clear the PreviousIDMatch here?
			response.ClearPreviousIDMatch()
		}

		// TODO do we id match on first auth?
		response.WithIDMatch()

		if req.Client.Opt["suk"] {
			response.Suk = req.Client.Suk
		}
	}

	if (req.Client.Cmd == "ident" || req.Client.Cmd == "enable") && identity != nil && !identity.Disabled {
		// TODO update hardlock and sqrlonly options
		log.Printf("Authenticated Idk: %#v", identity)
		authURL, err := api.authenticateIdentity(identity)
		if err != nil {
			log.Printf("Failed saving identity: %v", err)
			w.Write(response.WithTransientError().WithCommandFailed().Encode())
			return
		}
		if req.Client.Opt["cps"] {
			log.Printf("Setting CPS Auth: %v", authURL)
			response.URL = authURL
		}
	}

	// fail the ident on account disable
	if req.Client.Cmd == "ident" && identity != nil && identity.Disabled {
		response.WithCommandFailed()
	}

	// store last response to check on next request
	respBytes := response.Encode()

	// TODO debug remove me
	decodedResp, _ := Sqrl64.DecodeString(string(respBytes))
	log.Printf("Response: %v", string(decodedResp))

	if (req.Client.Cmd == "ident" || req.Client.Cmd == "enable") && !accountDisabled {
		// TODO do we need to expect more queries from the SQRL client after ident?

		// for non-CPS we save the state back to the PagNut for redirect on polling
		if !req.Client.Opt["cps"] {
			err = api.hoard.Save(hoardCache.PagNut, &HoardCache{
				State:        "authenticated",
				RemoteIP:     hoardCache.RemoteIP,
				OriginalNut:  hoardCache.OriginalNut,
				PagNut:       hoardCache.PagNut,
				LastRequest:  req,
				Identity:     identity,
				LastResponse: respBytes,
			}, api.NutExpiration)
			if err != nil {
				log.Printf("Failed saving to hoard: %v", err)
				response.WithTransientError()
			}
			log.Printf("Saved pagnut %v in hoard", nut)
		}
	}

	// always save back the new nut
	err = api.hoard.Save(nut, &HoardCache{
		State:        "associated",
		RemoteIP:     hoardCache.RemoteIP,
		OriginalNut:  hoardCache.OriginalNut,
		PagNut:       hoardCache.PagNut,
		LastRequest:  req,
		LastResponse: respBytes,
	}, api.NutExpiration)
	if err != nil {
		log.Printf("Failed saving to hoard: %v", err)
		response.WithTransientError()
	}
	log.Printf("Saved nut %v in hoard", nut)

	// query

	w.Write(respBytes)
}
