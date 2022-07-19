package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/satorunooshie/asn"

	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	requestFilePath        = "testdata/request.txt"
	invalidRequestFilePath = "testdata/invalid_request.txt"
	responseFilePath       = "testdata/response.json"
	ica0FilePath           = "testdata/ICA0.cer"
	ica1FilePath           = "testdata/ICA1.cer"
	rootCAFilePath         = "testdata/Root-CA.cer"
	rawFilePath            = "testdata/raw.txt"

	payload        = `{"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}}`
	invalidPayload = `{"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g77","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}}`
)

func path(s string) string {
	return filepath.Join(s)
}

func generateECDSA(curve elliptic.Curve, template *x509.Certificate, rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, *ecdsa.PrivateKey, error) {
	privkey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	isRootCA := rootKey == nil
	if isRootCA {
		rootCert = template
		rootKey = privkey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, &privkey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate: %v\n", err)
	}

	if isRootCA {
		f, err := os.Create(path(rootCAFilePath))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to create file: %v\n", err)
		}
		_, _ = f.Write(derBytes)
		defer func() {
			_ = f.Close()
		}()
	} else {
		if template.KeyUsage == x509.KeyUsageDigitalSignature {
			f, err := os.Create(path(ica0FilePath))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to create file: %v\n", err)
			}
			_, _ = f.Write(derBytes)
			defer func() {
				_ = f.Close()
			}()
		} else {
			f, err := os.Create(path(ica1FilePath))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to create file: %v\n", err)
			}
			_, _ = f.Write(derBytes)
			defer func() {
				_ = f.Close()
			}()
		}
	}

	der := make([]byte, base64.StdEncoding.EncodedLen(len(derBytes)))
	base64.StdEncoding.Encode(der, derBytes)

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse certificate: %v\n", err)
	}
	return cert, der, privkey, nil
}

func main() {
	log.SetFlags(log.Llongfile)

	gmt, err := time.LoadLocation("GMT")
	if err != nil {
		log.Println(err)
		return
	}
	rootTmpl := x509.Certificate{
		Version:            3,
		SerialNumber:       big.NewInt(3298319966700653461),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		Issuer: pkix.Name{
			CommonName:         "Apple Root CA - G3",
			OrganizationalUnit: []string{"Apple Certification Authority"},
			Organization:       []string{"Apple Inc."},
			Country:            []string{"US"},
		},
		Subject: pkix.Name{
			CommonName:         "Apple Root CA - G3",
			OrganizationalUnit: []string{"Apple Certification Authority"},
			Organization:       []string{"Apple Inc."},
			Country:            []string{"US"},
		},
		NotBefore:             time.Date(2014, time.April, 30, 18, 19, 06, 0, gmt),
		NotAfter:              time.Date(2039, time.April, 30, 18, 19, 06, 0, gmt),
		SubjectKeyId:          []byte(`BB:B0:DE:A1:58:33:88:9A:A4:8A:99:DE:BE:BD:EB:AF:DA:CB:24:AB`),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
	}
	rootCer, rootDer, rootPrivkey, err := generateECDSA(elliptic.P384(), &rootTmpl, &rootTmpl, nil)
	if err != nil {
		log.Println(err)
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("failed to generate serial number: %v\n", err)
		return
	}
	icaTmpl := x509.Certificate{
		Version:            3,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		Issuer:             rootTmpl.Subject,
		Subject: pkix.Name{
			CommonName:         "Apple Worldwide Developer Relations Certification Authority",
			OrganizationalUnit: []string{"G6"},
			Organization:       []string{"Apple Inc."},
			Country:            []string{"US"},
		},
		NotBefore:             time.Date(2021, time.March, 17, 20, 37, 10, 0, gmt),
		NotAfter:              time.Date(2036, time.March, 19, 00, 00, 00, 0, gmt),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		AuthorityKeyId:        []byte(`BB:B0:DE:A1:58:33:88:9A:A4:8A:99:DE:BE:BD:EB:AF:DA:CB:24:AB`),
		OCSPServer:            []string{"http://ocsp.apple.com/ocsp03-applerootcag3"},
		SubjectKeyId:          []byte(`3F:2F:94:23:51:D3:50:C9:9A:28:3D:ED:B0:7C:E5:CF:A5:90:62:99`),
		CRLDistributionPoints: []string{"http://crl.apple.com/applerootcag3.crl"},
		KeyUsage:              x509.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
	}
	icaCer, icaDer, icaPrivkey, err := generateECDSA(elliptic.P384(), &icaTmpl, rootCer, rootPrivkey)
	if err != nil {
		log.Println(err)
		return
	}

	dsTmpl := x509.Certificate{
		Version:            3,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		Issuer:             icaTmpl.Subject,
		Subject: pkix.Name{
			CommonName:         "Prod ECC Mac App Store and iTunes Store Receipt Signing",
			OrganizationalUnit: []string{"Apple Worldwide Developer Relations"},
			Organization:       []string{"Apple Inc."},
			Country:            []string{"US"},
		},
		NotBefore:             time.Date(2021, time.August, 25, 02, 50, 34, 0, gmt),
		NotAfter:              time.Date(2023, time.September, 24, 02, 50, 33, 0, gmt),
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        []byte(`3F:2F:94:23:51:D3:50:C9:9A:28:3D:ED:B0:7C:E5:CF:A5:90:62:99`),
		IssuingCertificateURL: []string{"http://certs.apple.com/wwdrg6.der"},
		OCSPServer:            []string{"http://ocsp.apple.com/ocsp03-wwdrg602"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			{1, 2, 840, 113635, 100, 5, 6, 1},
		},
		SubjectKeyId: []byte(`23:82:98:C0:6A:FF:FD:4B:E6:29:AF:56:6A:97:D6:80:98:7A:AA:CC`),
		KeyUsage:     x509.KeyUsage(x509.KeyUsageDigitalSignature),
	}
	_, dsDer, dsPrivkey, err := generateECDSA(elliptic.P256(), &dsTmpl, icaCer, icaPrivkey)
	if err != nil {
		log.Println(err)
		return
	}

	chain := new(cert.Chain)

	_ = chain.Add(dsDer)
	_ = chain.Add(icaDer)
	_ = chain.Add(rootDer)

	h := jws.NewHeaders()
	_ = h.Set(jws.X509CertChainKey, chain)

	key, err := jwk.FromRaw(dsPrivkey)
	if err != nil {
		log.Printf("failed to create symmetric key: %v\n", err)
		return
	}

	signOpts := []jws.SignOption{
		jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(h)),
	}
	buf, err := jws.Sign([]byte(payload), signOpts...)
	if err != nil {
		log.Printf("failed to sign: %v\n", err)
		return
	}
	log.Printf("dump request: %s\n", buf)
	reqf, err := os.Create(path(requestFilePath))
	if err != nil {
		log.Println(err)
		return
	}
	if _, err := reqf.Write(buf); err != nil {
		log.Println(err)
		return
	}
	_ = reqf.Close()

	// invalid payload
	sep := []byte(".")
	spReq := bytes.Split(buf, sep)
	invalidReqf, err := os.Create(path(invalidRequestFilePath))
	if err != nil {
		log.Println(err)
		return
	}
	ipb := []byte(invalidPayload)
	dbuf := make([]byte, base64.StdEncoding.EncodedLen(len(ipb)))
	base64.StdEncoding.Encode(dbuf, ipb)
	if _, err := invalidReqf.Write(append(spReq[0], append(sep, append(dbuf, append(sep, spReq[2]...)...)...)...)); err != nil {
		log.Println(err)
		return
	}
	_ = invalidReqf.Close()

	log.Printf("dump root der: %s\n", rootDer)
	rootf, err := os.Create(path(rawFilePath))
	if err != nil {
		log.Println(err)
		return
	}
	if _, err := rootf.Write(rootDer); err != nil {
		log.Println(err)
		return
	}
	_ = rootf.Close()

	verified, err := jws.Verify(buf, []jws.VerifyOption{jws.WithKeyProvider(asn.NewKeyProvider(asn.NewFileRootCAFetcher(path(rootCAFilePath))))}...)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("dump response: %s\n", verified)
	resf, err := os.Create(path(responseFilePath))
	if err != nil {
		log.Println(err)
		return
	}
	if _, err := resf.Write(verified); err != nil {
		log.Println(err)
		return
	}
	_ = resf.Close()
}
