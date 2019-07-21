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
var port int
var help string

func main() {
	flag.StringVar(&keyFile, "key", "", "key.pem file for TLS")
	flag.StringVar(&certFile, "cert", "", "cert.pem file for TLS")
	flag.StringVar(&hostOverride, "h", "", "hostname used in creating URLs")
	flag.StringVar(&rootPath, "path", "", "path used as the root for the SQRL handlers (if not /)")
	flag.IntVar(&port, "p", 8000, "port to listen on")
	flag.StringVar(&help, "help", "", "print usage")

	flag.Parse()

	if len(flag.Args()) > 0 || help != "" {
		flag.PrintDefaults()
		return
	}

	tree, err := ssp.NewRandomTree(8)
	if err != nil {
		log.Fatalf("Failed to create tree: %v", err)
	}

	authStore := ssp.NewMapAuthStore()
	hoard := ssp.NewMapHoard()
	// redisClient := redis.NewUniversalClient(&redis.UniversalOptions{})
	// hoard := redishoard.NewHoard(redisClient)
	sspAPI := ssp.NewSqrlSspAPI(tree,
		hoard,
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

	listenOn := fmt.Sprintf(":%d", port)
	if certFile != "" && keyFile != "" {
		log.Printf("Listening TLS on port %d", port)
		err = http.ListenAndServeTLS(listenOn, certFile, keyFile, nil)
	} else {
		log.Printf("Listening on port %d", port)
		err = http.ListenAndServe(listenOn, nil)
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
