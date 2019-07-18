package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	ssp "github.com/smw1218/sqrl-ssp"
	"github.com/smw1218/sqrl-ssp/server/homepagehandler"
)

var certFile, keyFile string
var hostOverride, rootPath string

func main() {
	flag.StringVar(&keyFile, "key", "", "key.pem file for TLS")
	flag.StringVar(&certFile, "cert", "", "cert.pem file for TLS")
	flag.StringVar(&hostOverride, "h", "", "hostname used in creating URLs")
	flag.StringVar(&rootPath, "path", "", "path used as the root for the SQRL handlers (if not /)")
	flag.Parse()
	tree, err := ssp.NewRandomTree(8)
	if err != nil {
		log.Fatalf("Failed to create tree: %v", err)
	}

	authStore := ssp.NewMapAuthStore()
	sspAPI := ssp.NewSqrlSspAPI(tree,
		ssp.NewMapHoard(),
		&auther{hostOverride, rootPath},
		authStore)
	sspAPI.HostOverride = hostOverride
	sspAPI.RootPath = rootPath

	// Add existing identity to test Pidk
	idSeed := &ssp.SqrlIdentity{
		Disabled: false,
		Idk:      "-hBaX3BE36R0dkRNSmmur9vNFuMwZG4FCEgcmKkrunM",
		Suk:      "yVBzTI2Q4HGBmWSMAc2DuoSx3ZubZweAdIKplTia4mI",
		Vuk:      "GdEBlxqMeZeHhjmEnWInBQTs0zcO6wkqc23o2oATfiw",
		Pidk:     "",
	}
	authStore.SaveIdentity(idSeed)

	hph := &homepagehandler.TemplatedAssets{
		API: sspAPI,
	}

	http.HandleFunc("/nut.sqrl", sspAPI.Nut)
	http.HandleFunc("/png.sqrl", sspAPI.PNG)
	http.HandleFunc("/pag.sqrl", sspAPI.Pag)
	http.HandleFunc("/cli.sqrl", sspAPI.Cli)
	http.HandleFunc("/", hph.Handle)

	if certFile != "" && keyFile != "" {
		log.Printf("Listening TLS on port 8000")
		err = http.ListenAndServeTLS(":8000", certFile, keyFile, nil)
	} else {
		log.Printf("Listening on port 8000")
		err = http.ListenAndServe(":8000", nil)
	}
	if err != nil {
		log.Printf("Failed server start: %v", err)
	}
}

type auther struct {
	Host string
	Path string
}

func (a *auther) AuthenticateIdentity(identity *ssp.SqrlIdentity) string {
	return fmt.Sprintf("https://%v%v/success.html?idk=%v", a.Host, a.Path, identity.Idk)
}

func (a *auther) SwapIdentities(newIdentity, oldIdentity *ssp.SqrlIdentity) error {
	// nothing to do here since we're not creating users
	return nil
}
func (a *auther) RemoveIdentity(identity *ssp.SqrlIdentity) error {
	// nothing to do here since we're not creating users
	return nil
}
