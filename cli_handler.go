package ssp

import (
	"fmt"
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

	// response mutates from here depending on available values
	response := NewCliResponse(Nut(nut), api.qry(nut))
	req, err := ParseCliRequest(r)
	if err != nil {
		log.Printf("Can't parse body or bad signature: %v", err)
		w.Write(response.WithClientFailure().Encode())
		return
	}
	// Signature is OK from here on!

	// defer writing the response and saving the new nut
	defer api.writeResponse(req, response, w)

	// TODO remove me
	spew.Dump(req)

	hoardCache, err := api.getAndDelete(Nut(nut))
	if err != nil {
		if err == ErrNotFound {
			log.Printf("Nut %v not found", nut)
			response.WithClientFailure().WithCommandFailed()
			return
		}
		log.Printf("Failed nut lookup: %v", err)
		response.WithTransientError().WithCommandFailed()
		return
	}
	response.HoardCache = hoardCache

	// validation checks
	err = api.requestValidations(hoardCache, req, r, response)
	if err != nil {
		return
	}

	// generate new nut
	nut, err = api.tree.Nut()
	if err != nil {
		log.Printf("Error generating nut: %v", err)
		response.WithTransientError()
		return
	}

	// new nut to the response from here on out
	response.Nut = nut
	response.Qry = api.qry(nut)

	// check if the same user has already been authenticated previously

	identity, err := api.authStore.FindIdentity(req.Client.Idk)
	if err != nil && err != ErrNotFound {
		log.Printf("Error looking up identity: %v", err)
		response.WithTransientError()
		return
	}

	// Check is we know about a previous identity
	previousIdentity, err := api.checkPreviousIdentity(req, response)
	if err != nil {
		return
	}

	if identity != nil {
		err := api.knownIdentity(req, response, identity)
		if err != nil {
			return
		}
	} else if req.Client.Cmd == "ident" {
		// create new identity from the request
		identity = req.Identity()
		// handle previous identity swap if the current identity is new
		err := api.checkPreviousSwap(previousIdentity, identity, response)
		if err != nil {
			return
		}

		// TODO do we id match on first auth?
		response.WithIDMatch()
	}
	api.setSuk(req, response, identity)

	// Finish authentication and saving
	api.finishCliResponse(req, response, identity, hoardCache)
}

func (api *SqrlSspAPI) writeResponse(req *CliRequest, response *CliResponse, w http.ResponseWriter) {
	respBytes := response.Encode()
	// TODO debug remove me
	decodedResp, _ := Sqrl64.DecodeString(string(respBytes))
	log.Printf("Response: %v", string(decodedResp))
	log.Printf("Encoded response: %v", string(respBytes))

	// always save back the new nut
	if response.HoardCache != nil {
		err := api.hoard.Save(response.Nut, &HoardCache{
			State:        "associated",
			RemoteIP:     response.HoardCache.RemoteIP,
			OriginalNut:  response.HoardCache.OriginalNut,
			PagNut:       response.HoardCache.PagNut,
			LastRequest:  req,
			LastResponse: respBytes,
		}, api.NutExpiration)
		if err != nil {
			log.Printf("Failed saving to hoard: %v", err)
			response.WithTransientError()
			respBytes = response.Encode()
		} else {
			log.Printf("Saved nut %v in hoard", response.Nut)
		}
	}
	w.Write(respBytes)
	log.Println()
}

func (api *SqrlSspAPI) setSuk(req *CliRequest, response *CliResponse, identity *SqrlIdentity) {
	if req.Client.Opt["suk"] {
		if identity != nil {
			response.Suk = identity.Suk
		} else if req.Client.Cmd == "ident" {
			response.Suk = req.Client.Suk
		}
	}
}

func (api *SqrlSspAPI) finishCliResponse(req *CliRequest, response *CliResponse, identity *SqrlIdentity, hoardCache *HoardCache) {
	accountDisabled := false
	if identity != nil {
		accountDisabled = identity.Disabled
	}
	if req.IsAuthCommand() && !accountDisabled {
		log.Printf("Authenticated Idk: %#v", identity)
		authURL, err := api.authenticateIdentity(identity)
		if err != nil {
			log.Printf("Failed saving identity: %v", err)
			response.WithTransientError().WithCommandFailed()
			return
		}
		if req.Client.Opt["cps"] {
			log.Printf("Setting CPS Auth: %v", authURL)
			response.URL = authURL
		}
	}

	// fail the ident on account disable
	if req.Client.Cmd == "ident" && accountDisabled {
		response.WithCommandFailed()
	}

	if req.IsAuthCommand() && !accountDisabled {
		// for non-CPS we save the state back to the PagNut for redirect on polling
		if !req.Client.Opt["cps"] {
			err := api.hoard.Save(hoardCache.PagNut, &HoardCache{
				State:       "authenticated",
				RemoteIP:    hoardCache.RemoteIP,
				OriginalNut: hoardCache.OriginalNut,
				PagNut:      hoardCache.PagNut,
				LastRequest: req,
				Identity:    identity,
			}, api.NutExpiration)
			if err != nil {
				log.Printf("Failed saving to hoard: %v", err)
				response.WithTransientError()
			}
			log.Printf("Saved pagnut %v in hoard", hoardCache.PagNut)
		}
	}
}

func (api *SqrlSspAPI) checkPreviousSwap(previousIdentity, identity *SqrlIdentity, response *CliResponse) error {
	if previousIdentity != nil {
		err := api.swapIdentities(previousIdentity, identity)
		if err != nil {
			log.Printf("Failed swapping identities: %v", err)
			response.WithTransientError().WithCommandFailed()
			return fmt.Errorf("identity swap error")
		}
		log.Printf("Swapped identity %#v for %#v", previousIdentity, identity)
		// TODO should we clear the PreviousIDMatch here?
		response.ClearPreviousIDMatch()
	}
	return nil
}

func (api *SqrlSspAPI) checkPreviousIdentity(req *CliRequest, response *CliResponse) (*SqrlIdentity, error) {
	var previousIdentity *SqrlIdentity
	var err error
	if req.Client.Pidk != "" {
		previousIdentity, err = api.authStore.FindIdentity(req.Client.Pidk)
		if err != nil && err != ErrNotFound {
			log.Printf("Error looking up previous identity: %v", err)
			response.WithTransientError()
			return nil, err
		}
	}
	if previousIdentity != nil {
		response.WithPreviousIDMatch()
	}
	return previousIdentity, nil
}

func (api *SqrlSspAPI) requestValidations(hoardCache *HoardCache, req *CliRequest, r *http.Request, response *CliResponse) error {
	// validate last response against this request
	if hoardCache.LastResponse != nil && !req.ValidateLastResponse(hoardCache.LastResponse) {
		response.WithCommandFailed()
		// this is intentionally after so nothing about last response leaks
		log.Printf("Last response %v and this one don't match: %v", string(hoardCache.LastResponse), string(req.Server))
		return fmt.Errorf("validation error")
	}

	// validate the IP if required
	if hoardCache.RemoteIP != api.RemoteIP(r) {
		if !req.Client.Opt["noiptest"] {
			log.Printf("Rejecting on IP mis-match orig: %v current: %v", hoardCache.RemoteIP, api.RemoteIP(r))
			response.WithCommandFailed()
			return fmt.Errorf("validation error")
		}
	} else {
		log.Printf("Matched IP addresses")
		response = response.WithIPMatch()
	}

	// validating the current request and associated Idk's match
	if hoardCache.LastRequest != nil && hoardCache.LastRequest.Client.Idk != req.Client.Idk {
		log.Printf("Identity mismatch orig: %v current %v", hoardCache.LastRequest.Client.Idk, req.Client.Idk)
		response.WithCommandFailed().WithClientFailure().WithBadIDAssociation()
		return fmt.Errorf("validation error")
	}

	return nil
}

func (api *SqrlSspAPI) knownIdentity(req *CliRequest, response *CliResponse, identity *SqrlIdentity) error {
	response.WithIDMatch()
	changed := false
	if req.IsAuthCommand() {
		changed = req.UpdateIdentity(identity)
	}
	if req.Client.Cmd == "enable" || req.Client.Cmd == "remove" {
		err := req.VerifyUrs(identity.Vuk)
		if err != nil {
			log.Printf("enable command failed urs validation")
			if identity.Disabled {
				response.WithSQRLDisabled()
			}
			response.WithClientFailure().WithCommandFailed()
			return fmt.Errorf("identity error")
		}
		if req.Client.Cmd == "enable" {
			log.Printf("Reenabled account: %v", identity.Idk)
			identity.Disabled = false
			changed = true
		} else if req.Client.Cmd == "remove" {
			err := api.removeIdentity(identity)
			if err != nil {
				log.Printf("Failed removing identity %v: %v", identity.Idk, err)
				response.WithClientFailure().WithCommandFailed()
				return fmt.Errorf("identity error")
			}
			log.Printf("removed identity %v", identity.Idk)
		}
	}
	if req.Client.Cmd == "disable" {
		identity.Disabled = true
		changed = true
	}

	if identity.Disabled {
		response.WithSQRLDisabled()
	}
	if changed {
		err := api.authStore.SaveIdentity(identity)
		if err != nil {
			log.Printf("Failed saving identity %v: %v", identity.Idk, err)
			response.WithClientFailure().WithCommandFailed()
			return fmt.Errorf("identity error")
		}
	}
	return nil
}
