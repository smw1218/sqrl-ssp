package ssp

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

// Nut implements the /nut.sqrl endpoint
// TODO sin, ask and 1-9 params
func (api *SqrlSspAPI) Nut(w http.ResponseWriter, r *http.Request) {
	nut, err := api.tree.Nut(nil)
	if err != nil {
		log.Printf("Failed generating nut: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	pagnut, err := api.tree.Nut(nil)
	if err != nil {
		log.Printf("Failed generating nut: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
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
		log.Printf("Failed to save a nut: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("Saved nut %v in hoard from %v", nut, hoardCache.RemoteIP)

	w.Header().Add("Content-Type", "application/x-www-form-urlencoded")
	values := make(url.Values)
	values.Add("nut", string(nut))
	values.Add("pag", string(pagnut))

	if referer := r.Header.Get("Referer"); referer != "" {
		values.Add("can", Sqrl64.EncodeToString([]byte(referer)))
	}

	_, err = w.Write([]byte(values.Encode()))
	if err != nil {
		log.Printf("Nut response write error: %v", err)
	}
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
	if nut == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Missing required nut parameter"))
		return
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

	png, err := qrcode.Encode(value, qrcode.Medium, -5)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed create of PNG"))
		return
	}

	w.Header().Add("Content-Type", "image/png")
	w.Write(png)
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

	w.Write([]byte(api.PagHandler(hoardCache.LastRequest.Client.Idk)))
}
