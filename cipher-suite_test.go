package tlsciphersuite

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestTLSCipherSuites(t *testing.T) {

	doRequest := func(client *http.Client) {
		res, err := client.Get("https://127.0.0.1:8443")
		if err != nil {
			t.Fatal(err)
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		t.Logf("Code: %d\n", res.StatusCode)
		t.Logf("Body: %s\n", body)
	}

	var (
		minVer       uint16
		maxVer       uint16
		cipherSuites []uint16
	)
	// test default
	t.Run("Default TLS", func(t *testing.T) {

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
}
