package server

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stephnangue/warden/core"
)

func TestIsLoopbackListenAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8400", true},
		{"[::1]:8400", true},
		{"localhost:8400", true},
		{"LOCALHOST:8400", true},
		{"[::ffff:127.0.0.1]:8400", true},
		{"[::ffff:0.0.0.0]:8400", false},
		{"0.0.0.0:8400", false},
		{"[::]:8400", false},
		{":8400", false},
		{"10.0.0.5:8400", false},
		{"warden:8400", false},
		{"nonsense", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.want, isLoopbackListenAddr(tt.addr))
		})
	}
}

func TestDevClientAddr(t *testing.T) {
	tests := []struct {
		listenAddr string
		want       string
	}{
		{"127.0.0.1:8400", "https://127.0.0.1:8400"},
		{"0.0.0.0:9400", "https://127.0.0.1:9400"},
		{"[::]:8400", "https://127.0.0.1:8400"},
		{":8400", "https://127.0.0.1:8400"},
		{"10.0.0.5:8400", "https://10.0.0.5:8400"},
		{"[::1]:8400", "https://[::1]:8400"},
	}
	for _, tt := range tests {
		t.Run(tt.listenAddr, func(t *testing.T) {
			assert.Equal(t, tt.want, devClientAddr("https", tt.listenAddr))
		})
	}
}

func TestPrintDevBanner_ListenAddr(t *testing.T) {
	result := &core.InitResult{RootToken: "root"}

	var loopback bytes.Buffer
	printDevBanner(&loopback, result, "127.0.0.1:8400", "", false)
	assert.NotContains(t, loopback.String(), "beyond this host's loopback")

	var wide bytes.Buffer
	printDevBanner(&wide, result, "0.0.0.0:9400", "/certs", false)
	assert.Contains(t, wide.String(), "The dev listener binds 0.0.0.0:9400, beyond this host's loopback")
	assert.Contains(t, wide.String(), "export WARDEN_CACERT=/certs/cert.pem")
	assert.Contains(t, wide.String(), "export WARDEN_ADDR=https://127.0.0.1:9400")
}
