package ssp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

type nutJSON struct {
	Nut        Nut `json:"nut"`
	Pagnut     Nut `json:"pag"`
	Expiration int `json:"exp"`
}

// Nut implements the /nut.sqrl endpoint
// TODO sin, ask and 1-9 params
func (api *SqrlSspAPI) Nut(w http.ResponseWriter, r *http.Request) {
	hoardCache, err := api.createAndSaveNut(r)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Add("Content-Type", "application/json")
		respObj := &nutJSON{
			Nut:        hoardCache.OriginalNut,
			Pagnut:     hoardCache.PagNut,
			Expiration: api.NutExpirationSeconds(),
		}
		enc, err := json.Marshal(respObj)
		if err != nil {
			log.Printf("Failed json encode: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(enc)
		return
	}
	w.Header().Add("Content-Type", "application/x-www-form-urlencoded")
	values := make(url.Values)
	values.Add("nut", string(hoardCache.OriginalNut))
	values.Add("pag", string(hoardCache.PagNut))
	values.Add("exp", fmt.Sprintf("%d", api.NutExpirationSeconds()))

	if referer := r.Header.Get("Referer"); referer != "" {
		values.Add("can", Sqrl64.EncodeToString([]byte(referer)))
	}

	_, err = w.Write([]byte(values.Encode()))
	if err != nil {
		log.Printf("Nut response write error: %v", err)
	}
}

func (api *SqrlSspAPI) createAndSaveNut(r *http.Request) (*HoardCache, error) {
	nut, err := api.tree.Nut()
	if err != nil {
		return nil, fmt.Errorf("Failed generating nut: %v", err)
	}
	pagnut, err := api.tree.Nut()
	if err != nil {
		return nil, fmt.Errorf("Failed generating nut: %v", err)
	}

	hoardCache := &HoardCache{
		State:       "issued",
		RemoteIP:    api.RemoteIP(r),
		OriginalNut: nut,
		PagNut:      pagnut,
	}
	// store the nut in the hoard
	api.hoard.Save(nut, hoardCache, api.NutExpiration)
	if err != nil {
		return nil, fmt.Errorf("Failed to save a nut: %v", err)
	}
	log.Printf("Saved nut %v in hoard from %v", nut, hoardCache.RemoteIP)
	return hoardCache, nil
}

func (api *SqrlSspAPI) getAndDelete(nut Nut) (*HoardCache, error) {
	hoardCache, err := api.hoard.GetAndDelete(Nut(nut))
	if err != nil {
		return nil, err
	}
	return hoardCache, nil
}

// PNG implements the /png.sqrl endpoint
func (api *SqrlSspAPI) PNG(w http.ResponseWriter, r *http.Request) {
	nut := r.URL.Query().Get("nut")
	var hoardCache *HoardCache
	var err error
	if nut == "" {
		// create a nut
		hoardCache, err = api.createAndSaveNut(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		nut = string(hoardCache.OriginalNut)
	}

	params := make(url.Values)
	params.Add("nut", nut)
	sqrlURL := &url.URL{
		Scheme:   SqrlScheme,
		Host:     api.Host(r),
		Path:     fmt.Sprintf("%v/cli.sqrl", api.RootPath),
		RawQuery: params.Encode(),
	}

	value := sqrlURL.String()

	png, err := qrcode.Encode(value, qrcode.Low, -5)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed create of PNG"))
		return
	}

	if hoardCache != nil {
		w.Header().Add("Sqrl-Nut", string(hoardCache.OriginalNut))
		w.Header().Add("Sqrl-Pag", string(hoardCache.PagNut))
		w.Header().Add("Sqrl-Exp", fmt.Sprintf("%d", api.NutExpirationSeconds()))
	}
	w.Header().Add("Content-Type", "image/png")
	w.Write(png)
}

type pagJSON struct {
	URL string `json:"url"`
}

// Pag implements the /pag.sqrl endpoint
func (api *SqrlSspAPI) Pag(w http.ResponseWriter, r *http.Request) {
	nut := r.URL.Query().Get("nut")
	if nut == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing required nut parameter"))
		return
	}
	pagnut := r.URL.Query().Get("pag")
	if pagnut == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing required pag parameter"))
		return
	}

	hoardCache, err := api.getAndDelete(Nut(pagnut))
	if err != nil {
		if err == ErrNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Printf("Failed nut lookup: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed nut lookup"))
		return
	}

	if hoardCache.OriginalNut != Nut(nut) {
		log.Printf("Got query for pagnut but original nut doesn't match")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if hoardCache.Identity == nil {
		log.Printf("Nil identity on pag hoardCache")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Missing identity"))
		return
	}

	if r.Header.Get("Accept") == "application/json" {
		w.Header().Add("Content-Type", "application/json")
		respObj := &pagJSON{
			URL: api.Authenticator.AuthenticateIdentity(hoardCache.Identity),
		}
		enc, err := json.Marshal(respObj)
		if err != nil {
			log.Printf("Failed json encode: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(enc)
		return
	}

	w.Write([]byte(api.Authenticator.AuthenticateIdentity(hoardCache.Identity)))
}
