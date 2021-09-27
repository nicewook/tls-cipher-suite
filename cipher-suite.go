package tlsciphersuite

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

var tlsVersionMap = map[uint16]string{
	0x0301: "VersionTLS10",
	0x0302: "VersionTLS11",
	0x0303: "VersionTLS12",
	0x0304: "VersionTLS13",

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	0x0300: "VersionSSL30",
}

func simpleHandler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("This is an example server\n"))
}

func connStateHook(c net.Conn, state http.ConnState) {
	if state == http.StateActive {
		if cc, ok := c.(*tls.Conn); ok {
			log.Printf("Negociated TLS version: %s\n", tlsVersionMap[cc.ConnectionState().Version])
			log.Printf("Negociated CipherSuite: %s\n", tls.CipherSuiteName(cc.ConnectionState().CipherSuite))
		}
	}
}

func NewTLSServer(minVersion, maxVersion uint16, cipherSuites []uint16) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", simpleHandler)

	cfg := &tls.Config{}
	if minVersion != 0 {
		cfg.MinVersion = minVersion
	}
	if maxVersion != 0 {
		cfg.MaxVersion = maxVersion
	}
	if len(cipherSuites) != 0 {
		cfg.CipherSuites = make([]uint16, len(cipherSuites))
		copy(cfg.CipherSuites, cipherSuites)
	}

	return &http.Server{
		Addr:      ":8443",
		ConnState: connStateHook,
		Handler:   mux,
		TLSConfig: cfg,
	}
}

func NewTLSClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}
}

func tlsConfigDefault() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func tlsConfigV10() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS10,
	}
}

func tlsConfigV12() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}
}

// func tlsConfigDefault() *tls.Config {
// 	return &tls.Config{
// 		InsecureSkipVerify: true,
// 	}
// }
