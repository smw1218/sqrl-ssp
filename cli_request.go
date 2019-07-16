package ssp

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
)

type QueryTuple struct {
	Key   string
	Value string
}

// ParseSqrlQuery copied from go's url.ParseQuery with some modifications
func ParseSqrlQuery(query string) (params map[string]string, err error) {
	params = make(map[string]string, 0)
	for query != "" {
		key := query
		// windoze :(
		if i := strings.Index(key, "\r\n"); i >= 0 {
			key, query = key[:i], key[i+2:]
		} else {
			query = ""
		}
		if key == "" {
			continue
		}
		value := ""
		if i := strings.Index(key, "="); i >= 0 {
			key, value = key[:i], key[i+1:]
		}
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		params[key] = value
	}
	return params, err
}

type ClientBody struct {
	Version []int
	Cmd     string
	Opt     map[string]bool
	Suk     string // Sqrl64.Encoded
	Vuk     string // Sqrl64.Encoded
	Pidk    string // Sqrl64.Encoded
	Idk     string // Sqrl64.Encoded
}

func (cb *ClientBody) PublicKey() (ed25519.PublicKey, error) {
	pubKey, err := Sqrl64.DecodeString(cb.Idk)
	if err != nil {
		return nil, err
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Idk")
	}
	return pubKey, nil
}

func (cb *ClientBody) PidkPublicKey() (ed25519.PublicKey, error) {
	pubKey, err := Sqrl64.DecodeString(cb.Pidk)
	if err != nil {
		return nil, err
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Pidk")
	}
	return pubKey, nil
}

func ClientBodyFromParams(params map[string]string) (*ClientBody, error) {
	cb := &ClientBody{}
	// TODO handle multiple versions and ranges
	version, err := strconv.Atoi(params["ver"])
	if err != nil {
		return nil, fmt.Errorf("failed parsing version \"%s\": %v", params["ver"], err)
	}
	cb.Version = []int{version}

	cb.Cmd = params["cmd"]

	opts := strings.Split(params["opt"], "~")
	cb.Opt = make(map[string]bool, len(opts))
	for _, opt := range opts {
		cb.Opt[opt] = true
	}

	cb.Suk = params["suk"]
	cb.Vuk = params["vuk"]
	cb.Pidk = params["pidk"]
	cb.Idk = params["idk"]

	return cb, nil
}

type SqrlIdentity struct {
	Disabled bool
	Idk      string
	Suk      string
	Vuk      string
	Pidk     string // TODO do we need to keep track of Pidk?
}

type CliRequest struct {
	Client           *ClientBody
	Server           []byte
	IdsSigningString []byte
	Ids              []byte
	Pids             []byte
	Urs              []byte
}

func (cr *CliRequest) Identity() *SqrlIdentity {
	return &SqrlIdentity{
		Idk:  cr.Client.Idk,
		Suk:  cr.Client.Suk,
		Vuk:  cr.Client.Vuk,
		Pidk: cr.Client.Pidk,
	}
}

func (cr *CliRequest) VerifySignature() error {
	pubKey, err := cr.Client.PublicKey()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, cr.IdsSigningString, cr.Ids) {
		return fmt.Errorf("signature verification failed")
	}
	// if pids or pidk exists, the signature must be valid
	if cr.Pids != nil || cr.Client.Pidk != "" {
		return cr.VerifyPidsSignature()
	}
	return nil
}

func (cr *CliRequest) VerifyPidsSignature() error {
	pubKey, err := cr.Client.PidkPublicKey()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, cr.IdsSigningString, cr.Pids) {
		return fmt.Errorf("pids signature verification failed")
	}
	return nil
}

func (cr *CliRequest) VerifyUrs(vuk string) error {
	if vuk == "" || cr.Urs == nil {
		return fmt.Errorf("vuk or urs not valid")
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(vuk)
	if err != nil {
		return fmt.Errorf("can't decode vuk")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid vuk")
	}

	if !ed25519.Verify(pubKey, cr.IdsSigningString, cr.Urs) {
		log.Printf("signature verification failed")
	}
	return nil
}

func (cr *CliRequest) ValidateLastResponse(lastRepsonse []byte) bool {
	equal := subtle.ConstantTimeCompare(cr.Server, lastRepsonse)
	return equal == 1
}

func ParseCliRequest(r *http.Request) (*CliRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading post body: %v", err)
	}
	defer r.Body.Close()
	log.Printf("Got body: %v", string(body))

	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("invalid cli.sqrl request: %v", err)
	}

	// TODO validate presence of required parameters
	signingString := params.Get("client")
	signingString += params.Get("server")

	decoded := make(map[string][]byte, len(params))
	for k, p := range params {
		dec, err := Sqrl64.DecodeString(p[0])
		if err != nil {
			return nil, fmt.Errorf("invalid cli.sqrl request: %v", err)
		}
		decoded[k] = dec
	}

	clientParams, err := ParseSqrlQuery(string(decoded["client"]))
	if err != nil {
		return nil, fmt.Errorf("invalid cli.sqrl client body: %v", err)
	}

	cb, err := ClientBodyFromParams(clientParams)
	if err != nil {
		return nil, fmt.Errorf("invalid client param: %v", err)
	}

	cli := &CliRequest{
		Client:           cb,
		Server:           []byte(params.Get("server")),
		IdsSigningString: []byte(signingString),
		Ids:              decoded["ids"],
		Pids:             decoded["pids"],
		Urs:              decoded["urs"],
	}

	// If we get here, we can return the cli along with the error
	err = cli.VerifySignature()
	return cli, err
}
