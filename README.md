# github.com/satorunooshie/asn
[![Go Reference](https://pkg.go.dev/badge/github.com/satorunooshie/asn.svg)](https://pkg.go.dev/github.com/satorunooshie/asn)

Library for validation of App Store Server Notifications V2.

# Usage

- Set by file(s).
Use NewFileRootCAFetcher.

- Set by url(s).
Use NewHTTPRootCAFetcher.

- Set by raw(s).
Use NewRawRootCAFetcher.

Recommended for use with the [jwx](https://github.com/lestrrat-go/jwx) created by [lestrrat-go](https://github.com/lestrrat-go).

```go
package asn

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jws"
)

//go:embed testdata/Root-CA.cer
var rootCA []byte

//go:embed testdata/request.txt
var request []byte

//go:embed testdata/raw.txt
var raw []byte

const (
	emptyCerPath = "testdata/empty.cer"
	cerPath      = "testdata/Root-CA.cer"
	cerURL       = "https://www.apple.com/certificateauthority/AppleRootCA-G3.cer"
)

func path(filename string) string {
	return filepath.Join(filename)
}

type fakeAppleServer struct{}

func (*fakeAppleServer) RoundTrip(r *http.Request) (*http.Response, error) {
	res := httptest.NewRecorder()
	if r.URL.Host == "www.apple.com" {
		_, _ = res.Write(rootCA)
	}
	if strings.Contains(r.URL.String(), "notfound") {
		res.WriteHeader(http.StatusNotFound)
	}
	return res.Result(), nil
}

func ExampleNewKeyProvider_byFile() {
	kp := NewKeyProvider(NewFileRootCAFetcher(cerPath))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}

func ExampleNewKeyProvider_byFiles() {
	emptyCerPath := path(emptyCerPath)
	optional := []string{cerPath}
	kp := NewKeyProvider(NewFileRootCAFetcher(emptyCerPath, optional...))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}

func ExampleNewKeyProvider_byUrl() {
	client := &http.Client{
		Transport: &fakeAppleServer{},
	}
	kp := NewKeyProvider(NewHTTPRootCAFetcher(client, cerURL))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}

func ExampleNewKeyProvider_byUrls() {
	const url = "http://localhost:8080/test.cer"
	client := &http.Client{
		Transport: &fakeAppleServer{},
	}
	optional := []string{cerURL}
	kp := NewKeyProvider(NewHTTPRootCAFetcher(client, url, optional...))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}

func ExampleNewKeyProvider_byRaw() {
	kp := NewKeyProvider(NewRawRootCAFetcher(raw))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}

func ExampleNewKeyProvider_byRaws() {
	kp := NewKeyProvider(NewRawRootCAFetcher([]byte(`test`), raw))
	opts := []jws.VerifyOption{jws.WithKeyProvider(kp)}
	verified, err := jws.Verify(request, opts...)
	fmt.Println(string(verified), err)
	// Output:
	// {"notificationType":"DID_CHANGE_RENEWAL_PREF","subtype":"DOWNGRADE","notificationUUID":"c92e001c-96d2-9ou5-q92p-32a5fy0d6g78","notificationVersion":"2.0","data":{"appAppleId":982253034,"bundleId":"hogehoge","bundleVersion":"269822910.1","environment":"Production","signedRenewalInfo":"...","signedTransactionInfo":"..."}} <nil>
}
```
