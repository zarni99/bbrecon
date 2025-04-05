package subdomain

import (
	"crypto/tls"
	"net/http"
	"time"
)

func createHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Timeout:	time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
