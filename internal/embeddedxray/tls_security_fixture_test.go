package embeddedxray

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	xnet "github.com/xtls/xray-core/common/net"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPinnedCertificateTLSIdentity(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OneTunnel test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, san                  string
		destination, leafPin, want bool
	}{
		{"CA-correct-IP", "127.0.0.1", true, false, true},
		{"CA-wrong-IP", "127.0.0.2", true, false, false},
		{"CA-missing-name", "127.0.0.1", false, false, false},
		{"explicit-leaf-pin", "127.0.0.1", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(tc.san)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
			pair, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			server.StartTLS()
			defer server.Close()
			pin := xtls.GenerateCertHash(root)
			if tc.leafPin {
				pin = xtls.GenerateCertHash(parsed)
			}
			config := &xtls.Config{PinnedPeerCertSha256: [][]byte{pin}}
			options := []xtls.Option{}
			if tc.destination {
				options = append(options, xtls.WithDestination(xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(server.Listener.Addr().(*net.TCPAddr).Port))))
			}
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			secured := tls.Client(conn, config.GetTLSConfig(options...))
			defer secured.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err = secured.HandshakeContext(ctx)
			if (err == nil) != tc.want {
				t.Fatalf("TLS verification: success=%v expected=%v", err == nil, tc.want)
			}
		})
	}
}
