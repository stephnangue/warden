package api

import (
	"net/http"
	"strconv"
	"strings"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const (
	ErrOutputStringRequest = "output a string, please"
)

type OutputStringError struct {
	*retryablehttp.Request
	TLSSkipVerify              bool
	ClientCACert, ClientCAPath string
	ClientCert, ClientKey      string
	finalCurlString            string
}

func (d *OutputStringError) Error() string {
	if d.finalCurlString == "" {
		cs, err := d.buildCurlString()
		if err != nil {
			return err.Error()
		}
		d.finalCurlString = cs
	}

	return ErrOutputStringRequest
}

func (d *OutputStringError) CurlString() (string, error) {
	if d.finalCurlString == "" {
		cs, err := d.buildCurlString()
		if err != nil {
			return "", err
		}
		d.finalCurlString = cs
	}
	return d.finalCurlString, nil
}

func (d *OutputStringError) buildCurlString() (string, error) {
	body, err := d.BodyBytes()
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("curl ")

	if d.TLSSkipVerify {
		b.WriteString("--insecure ")
	}
	if d.Method != http.MethodGet {
		b.WriteString("-X ")
		b.WriteString(d.Method)
		b.WriteByte(' ')
	}
	if d.ClientCACert != "" {
		b.WriteString("--cacert '")
		b.WriteString(strings.ReplaceAll(d.ClientCACert, "'", "'\"'\"'"))
		b.WriteString("' ")
	}
	if d.ClientCAPath != "" {
		b.WriteString("--capath '")
		b.WriteString(strings.ReplaceAll(d.ClientCAPath, "'", "'\"'\"'"))
		b.WriteString("' ")
	}
	if d.ClientCert != "" {
		b.WriteString("--cert '")
		b.WriteString(strings.ReplaceAll(d.ClientCert, "'", "'\"'\"'"))
		b.WriteString("' ")
	}
	if d.ClientKey != "" {
		b.WriteString("--key '")
		b.WriteString(strings.ReplaceAll(d.ClientKey, "'", "'\"'\"'"))
		b.WriteString("' ")
	}
	if len(body) > 0 {
		b.WriteString("-d '")
		b.WriteString(strings.ReplaceAll(string(body), "'", "'\"'\"'"))
		b.WriteString("' ")
	}
	b.WriteString(strconv.Quote(d.URL.String()))

	return b.String(), nil
}