package ssp

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
)

// As specified https://www.grc.com/sqrl/semantics.htm

// TIF bitflags
const (
	TIFIDMatch              = 0x1
	TIFPreviousIDMatch      = 0x2
	TIFIPMatched            = 0x4
	TIFSQRLDisabled         = 0x8
	TIFFunctionNotSupported = 0x10
	TIFTransientError       = 0x20
	TIFCommandFailed        = 0x40
	TIFClientFailure        = 0x80
	TIFBadIDAssociation     = 0x100
)

// CliResponse encodes a response to the SQRL client
type CliResponse struct {
	Version []int
	Nut     Nut
	TIF     uint32
	Qry     string
	URL     string
	Sin     string
	Suk     string
	Ask     string
	Can     string
}

func NewCliResponse(nut Nut, qry string) *CliResponse {
	return &CliResponse{
		Version: []int{1},
		Nut:     nut,
		Qry:     qry,
	}
}

func (cr *CliResponse) WithClientFailure() *CliResponse {
	cr.TIF |= TIFClientFailure
	return cr
}

func (cr *CliResponse) WithCommandFailed() *CliResponse {
	cr.TIF |= TIFCommandFailed
	return cr
}

func (cr *CliResponse) WithSQRLDisabled() *CliResponse {
	cr.TIF |= TIFSQRLDisabled
	return cr
}

func (cr *CliResponse) WithTransientError() *CliResponse {
	cr.TIF |= TIFTransientError
	return cr
}

func (cr *CliResponse) WithIDMatch() *CliResponse {
	cr.TIF |= TIFIDMatch
	return cr
}

func (cr *CliResponse) WithPreviousIDMatch() *CliResponse {
	cr.TIF |= TIFPreviousIDMatch
	return cr
}

func (cr *CliResponse) ClearPreviousIDMatch() *CliResponse {
	cr.TIF = cr.TIF &^ TIFPreviousIDMatch
	return cr
}

func (cr *CliResponse) WithIPMatch() *CliResponse {
	cr.TIF |= TIFIPMatched
	return cr
}

func (cr *CliResponse) WithBadIDAssociation() *CliResponse {
	cr.TIF |= TIFBadIDAssociation
	return cr
}

func (cr *CliResponse) Encode() []byte {
	var b bytes.Buffer

	// TODO be less lazy and support ranges
	b.WriteString("ver=")
	for i, v := range cr.Version {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(v))
	}
	b.WriteString("\r\n")

	b.WriteString(fmt.Sprintf("nut=%v\r\n", cr.Nut))

	b.WriteString(fmt.Sprintf("tif=%x\r\n", cr.TIF))

	b.WriteString(fmt.Sprintf("qry=%v\r\n", cr.Qry))

	if cr.URL != "" {
		b.WriteString(fmt.Sprintf("url=%v\r\n", cr.URL))
	}

	if cr.Sin != "" {
		b.WriteString(fmt.Sprintf("sin=%v\r\n", cr.Sin))
	}

	if cr.Suk != "" {
		b.WriteString(fmt.Sprintf("suk=%v\r\n", cr.Suk))
	}

	// TODO Ask

	if cr.Can != "" {
		b.WriteString(fmt.Sprintf("can=%v\r\n", cr.Can))
	}

	encoded := Sqrl64.EncodeToString(b.Bytes())
	log.Printf("Encoded response: <%v>", encoded)
	return []byte(encoded)
}
