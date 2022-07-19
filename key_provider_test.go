package asn

import (
	"bytes"
	"net/http"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	requestPath        = "testdata/request.txt"
	invalidRequestPath = "testdata/invalid_request.txt"
	notFoundCerPath    = "testdata/notFound.cer"
)

func TestVerify(t *testing.T) {
	type args struct {
		fetchers []RootCAFetcher
		opts     []jws.VerifyOption
	}
	tests := []struct {
		name    string
		args    args
		req     string
		res     string
		wantErr bool
	}{
		{
			name: "is not from Apple",
			args: args{
				fetchers: []RootCAFetcher{
					NewFileRootCAFetcher(path(emptyCerPath)),
					NewHTTPRootCAFetcher(&http.Client{Transport: &fakeAppleServer{}}, "http://localhost:8080/isAppleFalse"),
					NewRawRootCAFetcher([]byte(``)),
				},
			},
			wantErr: true,
		},
		{
			name: "not found",
			args: args{
				fetchers: []RootCAFetcher{
					NewFileRootCAFetcher(path(notFoundCerPath)),
					NewHTTPRootCAFetcher(&http.Client{Transport: &fakeAppleServer{}}, "http://localhost:8080/notfound"),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid signature",
			args: args{
				fetchers: []RootCAFetcher{
					NewFileRootCAFetcher(path(cerPath)),
				},
			},
			req:     invalidRequestPath,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, fetcher := range tt.args.fetchers {
				kp := NewKeyProvider(fetcher)
				opts := append([]jws.VerifyOption{jws.WithKeyProvider(kp)}, tt.args.opts...)
				if tt.req == "" {
					tt.req = requestPath
				}
				actual, err := jws.Verify(read(t, path(tt.req)), opts...)
				t.Log(err)
				if tt.wantErr != (err != nil) {
					t.Error(err)
				}
				if expected := read(t, tt.res); !tt.wantErr && !bytes.Equal(expected, actual) {
					t.Errorf("expected: %s, but actual: %s\n", expected, actual)
				}
			}
		})
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()

	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
