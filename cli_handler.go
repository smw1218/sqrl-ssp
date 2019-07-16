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

	hoardCache, err := api.GetAndDelete(Nut(nut))
	if err != nil {
		if err == NotFoundError {
			log.Printf("Nut %v not found", nut)
			w.Write(response.WithClientFailure().WithCommandFailed().Encode())
			return
		} else {
			log.Printf("Failed nut lookup: %v", err)
			w.Write(response.WithTransientError().WithCommandFailed().Encode())
			return
		}
	}

	// validate last response agains this request
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
	nut, err = api.tree.Nut(nil)
	if err != nil {
		log.Printf("Error generating nut: %v", err)
		w.Write(response.WithTransientError().Encode())
		return
	}

	response.Nut = nut
	response.Qry = api.Qry(nut)

	// check if the same user has already been authenticated previously
	accountDisabled := false
	identity, err := api.FindIdentity(req.Client.Idk)
	if err != nil && err != NotFoundError {
		log.Printf("Error looking up identity: %v", err)
		w.Write(response.WithTransientError().Encode())
		return
	}

	var previousIdentity *SqrlIdentity
	if req.Client.Pidk != "" {
		previousIdentity, err = api.FindIdentity(req.Client.Pidk)
		if err != nil && err != NotFoundError {
			log.Printf("Error looking up previous identity: %v", err)
			w.Write(response.WithTransientError().Encode())
			return
		}
	}
	if previousIdentity != nil {
		response.WithPreviousIDMatch()
	}

	if identity != nil {
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
				// TODO save back to store
				identity.Disabled = false
			} else if req.Client.Cmd == "remove" {
				log.Printf("removed identity %v", identity.Idk)
				api.Authenticated.Delete(identity.Idk)
			}
		}
		if req.Client.Cmd == "disable" {
			// TODO save back to store
			identity.Disabled = true
		}

		if identity.Disabled {
			response.WithSQRLDisabled()
		}
	} else if req.Client.Cmd == "ident" {
		saveIdentity := req.Identity()

		// handle previous identity swap
		if previousIdentity != nil {
			err := api.SwapIdentities(previousIdentity, saveIdentity)
			if err != nil {
				log.Printf("Failed swapping identities: %v", err)
				w.Write(response.WithTransientError().WithCommandFailed().Encode())
				return
			}
			// TODO should we clear the PreviousIDMatch here?
			response.ClearPreviousIDMatch()
		}

		log.Printf("Authenticated Idk: %#v", saveIdentity)
		api.Authenticated.Store(saveIdentity.Idk, saveIdentity)
		// TODO do we id match on first auth?
		response.WithIDMatch()

		if req.Client.Opt["suk"] {
			response.Suk = req.Client.Suk
		}
	}

	if (req.Client.Cmd == "ident" || req.Client.Cmd == "enable") && req.Client.Opt["cps"] && !accountDisabled {
		authURL := api.PagHandler(req.Client.Idk)
		log.Printf("Setting CPS Auth: %v", authURL)
		response.URL = authURL
	}

	// fail the ident on account disable
	if (req.Client.Cmd == "ident" || req.Client.Cmd == "enable") && accountDisabled {
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
				LastResponse: respBytes,
			}, api.NutExpiration)
			if err != nil {
				log.Printf("Failed saving to hoard: %v", err)
				response.WithTransientError()
			}
			log.Printf("Saved nut %v in hoard", nut)
		}
	}
	if req.Client.Cmd == "query" {
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
	}
	// query

	w.Write(respBytes)
}
