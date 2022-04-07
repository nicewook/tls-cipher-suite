package tlsciphersuite

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTLSCipherSuites(t *testing.T) {

	doRequest := func(client *http.Client) {
		res, err := client.Get("https://127.0.0.1:8443")
		if err != nil {
			t.Log(err)
			return
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		t.Logf("Code: %d\n", res.StatusCode)
		t.Logf("Body: %s\n", body)
	}

	// test default
	t.Run("Default TLS", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		client := NewTLSClient(tlsConfigDefault())
		doRequest(client)
	})

	// test maxVersion TLS
	t.Run("maxVersion TLSv1.2", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		maxVer = uint16(tls.VersionTLS12)
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		client := NewTLSClient(tlsConfigDefault())
		doRequest(client)
	})

	// test client maxVersion TLSv1.0
	t.Run("client maxVersion TLSv1.0", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		client := NewTLSClient(tlsConfigV10())
		doRequest(client)
	})

	// test specific CipherSuite - RSA certificates
	t.Run("server specific CipherSuite - RSA", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		minVer = tls.VersionTLS12
		maxVer = tls.VersionTLS12
		cipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		t.Log("expect: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		client := NewTLSClient(tlsConfigDefault())
		doRequest(client)
	})

	// test specific CipherSuite - ECDSA certificates
	t.Run("server specific CipherSuite - ECDSA", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		minVer = tls.VersionTLS12
		maxVer = tls.VersionTLS12
		cipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.ecdsa.cert", "server.ecdsa.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		t.Log("expect: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
		client := NewTLSClient(tlsConfigDefault())
		doRequest(client)
	})
	// test specific CipherSuite - RSA certificates
	t.Run("server specific CipherSuite - SHA384", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		minVer = tls.VersionTLS12
		maxVer = tls.VersionTLS12
		cipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.cert", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				if strings.Contains(err.Error(), "TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher") {
					t.Log("TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher")
				} else {
					t.Error(err)
				}
			}
		}()
		time.Sleep(1 * time.Second)

		t.Log("expect: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
		client := NewTLSClient(tlsConfigDefault())
		doRequest(client)
	})

	// test client max version is lower then server
	t.Run("client max version is lower then server", func(t *testing.T) {
		var (
			minVer       uint16
			maxVer       uint16
			cipherSuites []uint16
		)
		minVer = tls.VersionTLS13
		server := NewTLSServer(minVer, maxVer, cipherSuites)
		defer func() {
			if err := server.Shutdown(context.TODO()); err != nil {
				t.Error(err) // failure/timeout shutting down the server gracefully
			}
		}()
		go func() {
			if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil &&
				err != http.ErrServerClosed {
				t.Error(err)
			}
		}()
		time.Sleep(1 * time.Second)

		client := NewTLSClient(tlsConfigV12())
		doRequest(client)
	})
}
