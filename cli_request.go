package ssp

import (
	"bytes"
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

// ParseSqrlQuery copied from go's url.ParseQuery with some modifications.
// The format is CRLF separated "key=value" pairs
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

// ClientBody holds the internal structure of the request "client" parameter;
// see https://www.grc.com/sqrl/protocol.htm in the section "The content of the “client” parameter."
// This is owned by a ClientRequest and probably shouldn't be used on it's own.
type ClientBody struct {
	Version []int           `json:"version"`
	Cmd     string          `json:"cmd"`
	Opt     map[string]bool `json:"opt"`
	Suk     string          `json:"suk"`  // Sqrl64.Encoded
	Vuk     string          `json:"vuk"`  // Sqrl64.Encoded
	Pidk    string          `json:"pidk"` // Sqrl64.Encoded
	Idk     string          `json:"idk"`  // Sqrl64.Encoded
	// valid values are 0,1,2; -1 means no value
	Btn int `json:"btn"`
}

// Encode returns the ClientBody encoded in Sqrl64
func (cb *ClientBody) Encode() []byte {
	if cb == nil {
		return []byte{}
	}
	var b bytes.Buffer

	// TODO be less lazy and support ranges
	b.WriteString("ver=")
	for i, v := range cb.Version {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(v))
	}
	b.WriteString("\r\n")

	b.WriteString(fmt.Sprintf("cmd=%v\r\n", cb.Cmd))

	if len(cb.Opt) > 0 {
		opts := make([]string, 0, len(cb.Opt))
		for k := range cb.Opt {
			opts = append(opts, k)
		}
		b.WriteString(fmt.Sprintf("opt=%v\r\n", strings.Join(opts, "~")))
	}

	b.WriteString(fmt.Sprintf("idk=%v\r\n", cb.Idk))

	if cb.Suk != "" {
		b.WriteString(fmt.Sprintf("suk=%v\r\n", cb.Suk))
	}

	if cb.Vuk != "" {
		b.WriteString(fmt.Sprintf("vuk=%v\r\n", cb.Vuk))
	}

	if cb.Pidk != "" {
		b.WriteString(fmt.Sprintf("pidk=%v\r\n", cb.Pidk))
	}

	encoded := Sqrl64.EncodeToString(b.Bytes())
	log.Printf("Encoded response: <%v>", encoded)
	return []byte(encoded)

}

// PublicKey decodes and validates the Idk as a ed25519.PublicKey
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

// PidkPublicKey decodes and validates the Pidk as a ed25519.PublicKey
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

// ClientBodyFromParams creates ClientBody from the output of ParseSqrlQuery
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

	cb.Btn, err = strconv.Atoi(params["btn"])
	if err != nil {
		cb.Btn = -1
	}

	return cb, nil
}

// CliRequest holds the data sent from the SQRL client to the /cli.sqrl endpoint
type CliRequest struct {
	Client        *ClientBody `json:"client"`
	ClientEncoded string      `json:"clientEncoded"`
	Server        string      `json:"server"`
	Ids           string      `json:"ids"`
	Pids          string      `json:"pids"`
	Urs           string      `json:"urs"`

	IPAddress string // saved here for reference
}

// Identity creates an identity from a request
func (cr *CliRequest) Identity() *SqrlIdentity {
	return &SqrlIdentity{
		Idk:      cr.Client.Idk,
		Suk:      cr.Client.Suk,
		Vuk:      cr.Client.Vuk,
		Pidk:     cr.Client.Pidk,
		SQRLOnly: cr.Client.Opt["sqrlonly"],
		Hardlock: cr.Client.Opt["hardlock"],
		Btn:      cr.Client.Btn,
	}
}

// SigningString creates the string that is signed by ids, pids and urs
func (cr *CliRequest) SigningString() []byte {
	if cr.ClientEncoded == "" {
		cr.ClientEncoded = string(cr.Client.Encode())
	}
	return []byte(cr.ClientEncoded + cr.Server)
}

// UpdateIdentity updates identity from request
func (cr *CliRequest) UpdateIdentity(identity *SqrlIdentity) bool {
	copy := &SqrlIdentity{}
	*copy = *identity
	identity.SQRLOnly = cr.Client.Opt["sqrlonly"]
	identity.Hardlock = cr.Client.Opt["hardlock"]
	return *identity == *copy
}

// IsAuthCommand is a command that authenticates (ident, enable)
func (cr *CliRequest) IsAuthCommand() bool {
	return cr.Client.Cmd == "ident" || cr.Client.Cmd == "enable"
}

// VerifySignature verifies the ids signature against
// the idk in the ClientBody. It also calls
// VerifyPidsSignature if necessary.
func (cr *CliRequest) VerifySignature() error {
	pubKey, err := cr.Client.PublicKey()
	if err != nil {
		return err
	}
	decodedIds, err := Sqrl64.DecodeString(cr.Ids)
	if err != nil {
		return fmt.Errorf("invalid ids: %v", err)
	}
	if !ed25519.Verify(pubKey, cr.SigningString(), decodedIds) {
		return fmt.Errorf("signature verification failed")
	}
	// if pids or pidk exists, the signature must be valid
	if cr.Pids != "" || cr.Client.Pidk != "" {
		return cr.VerifyPidsSignature()
	}
	return nil
}

// VerifyPidsSignature verifies the pids signature against
// the pidk in the ClientBody
func (cr *CliRequest) VerifyPidsSignature() error {
	pubKey, err := cr.Client.PidkPublicKey()
	if err != nil {
		return err
	}
	decodedPids, err := Sqrl64.DecodeString(cr.Pids)
	if err != nil {
		return fmt.Errorf("invalid pids: %v", err)
	}
	if !ed25519.Verify(pubKey, cr.SigningString(), decodedPids) {
		return fmt.Errorf("pids signature verification failed")
	}
	return nil
}

// VerifyUrs validates a urs signature against a passed in vuk.
// This call will fail if the urs doesn't exist because it is required
// for several operations. Don't call this if you don't need it.
func (cr *CliRequest) VerifyUrs(vuk string) error {
	if vuk == "" || cr.Urs == "" {
		return fmt.Errorf("vuk or urs not valid")
	}
	decodedUrs, err := Sqrl64.DecodeString(cr.Urs)
	if err != nil {
		return fmt.Errorf("invalid urs: %v", err)
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(vuk)
	if err != nil {
		return fmt.Errorf("can't decode vuk")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid vuk")
	}

	if !ed25519.Verify(pubKey, cr.SigningString(), decodedUrs) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ValidateLastResponse checks to make sure the response on this request
// matches a stored on that's passed in.
func (cr *CliRequest) ValidateLastResponse(lastRepsonse []byte) bool {
	equal := subtle.ConstantTimeCompare([]byte(cr.Server), lastRepsonse)
	return equal == 1
}

// ParseCliRequest parses and validates the request. The CliRequest
// can be trusted if no error is returned as the signatures have been
// checked.
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

	cli := &CliRequest{
		ClientEncoded: params.Get("client"),
		Server:        params.Get("server"),
		Ids:           params.Get("ids"),
		Pids:          params.Get("pids"),
		Urs:           params.Get("urs"),
	}

	decodedClient, err := Sqrl64.DecodeString(cli.ClientEncoded)
	if err != nil {
		return nil, fmt.Errorf("incalid client parameter: %v", err)
	}
	clientParams, err := ParseSqrlQuery(string(decodedClient))
	if err != nil {
		return nil, fmt.Errorf("invalid cli.sqrl client body: %v", err)
	}

	cli.Client, err = ClientBodyFromParams(clientParams)
	if err != nil {
		return nil, fmt.Errorf("invalid client param: %v", err)
	}

	// If we get here, we can return the cli along with the error
	err = cli.VerifySignature()
	return cli, err
}

// Encode creates the form encoded POST body from CliRequest
func (cr *CliRequest) Encode() string {
	req := make(url.Values)
	if cr.ClientEncoded != "" {
		req.Add("client", cr.ClientEncoded)
	} else {
		req.Add("client", string(cr.Client.Encode()))
	}
	req.Add("server", string(cr.Server))

	req.Add("ids", cr.Ids)
	if cr.Pids != "" {
		req.Add("pids", cr.Pids)
	}
	if cr.Urs != "" {
		req.Add("urs", cr.Urs)
	}

	return req.Encode()
}
