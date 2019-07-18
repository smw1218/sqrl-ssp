package homepagehandler

import (
	"log"
	"mime"
	"net/http"
	"path"
	"strings"
	"text/template"

	ssp "github.com/smw1218/sqrl-ssp"
	"github.com/smw1218/sqrl-ssp/server/homepage"
)

var sqrljs *template.Template

type TemplatedAssets struct {
	API *ssp.SqrlSspAPI
}

type jsData struct {
	RootURL string
}

func (ta *TemplatedAssets) Handle(w http.ResponseWriter, r *http.Request) {
	assetName := ""
	if r.URL.Path == "/" {
		assetName = "sqrl_demo.html"
	} else {
		assetName = strings.TrimLeft(r.URL.Path, "/")
	}

	if assetName == "" {
		log.Printf("No asset for path %v", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	bytes, err := homepage.Asset(assetName)
	if err != nil {
		log.Printf("Error getting %v: %v", assetName, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if assetName == "sqrlapi.js" {
		if sqrljs == nil {
			sqrljs, err = template.New("js").Parse(string(bytes))
			if err != nil {
				log.Printf("failed parsing template for sqrlapi.js: %v", err)
			}
		}
		// check again in case of error
		if sqrljs != nil {
			w.Header().Add("Content-Type", "application/javascript")
			err := sqrljs.Execute(w, jsData{ta.API.HTTPSRoot(r).String()})
			if err != nil {
				log.Printf("Failed template execute")
			}
			return
		}
	}

	ct := mime.TypeByExtension(path.Ext(assetName))
	if ct != "" {
		w.Header().Add("Content-Type", ct)
	}
	w.Write(bytes)
}
