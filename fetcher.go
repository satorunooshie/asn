package asn

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
)

// RootCAFetcher is an interface that fetches Root CA.
type RootCAFetcher interface {
	// Fetch returns Root CAs.
	Fetch(ctx context.Context) ([][]byte, error)
}

// HTTPRootCAFetcher implements RootCAFetcher via HTTP.
type HTTPRootCAFetcher struct {
	client *http.Client
	urls   []string
}

// NewHTTPRootCAFetcher returns a new HTTPRootCAFetcher.
// At least one url that returns Root CA must be set.
// Optional string argument is for setting multiple urls that returns Root CA.
// if *http.Client is nil, http.DefaultClient is used.
func NewHTTPRootCAFetcher(client *http.Client, url string, optional ...string) *HTTPRootCAFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPRootCAFetcher{
		client: client,
		urls:   append([]string{url}, optional...),
	}
}

// Fetch returns the Root CAs that were successfully fetched via http and an error
// if there's a problem with http access.
func (f *HTTPRootCAFetcher) Fetch(ctx context.Context) ([][]byte, error) {
	rootCAs := make([][]byte, 0, len(f.urls))
	for _, url := range f.urls {
		b, err := f.fetch(ctx, url)
		if err != nil {
			return rootCAs, err
		}
		dbuf := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
		base64.StdEncoding.Encode(dbuf, b)
		rootCAs = append(rootCAs, dbuf)
	}
	return rootCAs, nil
}

func (f *HTTPRootCAFetcher) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("url: %s, code: %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// FileRootCAFetcher implements RootCAFetcher via files.
type FileRootCAFetcher struct {
	paths  []string
	rootCA [][]byte
}

// NewFileRootCAFetcher returns a new FileRootCAFetcher.
// Optional string argument is for setting multiple Root CA file paths.
// At least one Root CA file path must be set.
func NewFileRootCAFetcher(cerpath string, optional ...string) *FileRootCAFetcher {
	return &FileRootCAFetcher{paths: append([]string{cerpath}, optional...)}
}

// Fetch returns the Root CAs from files set by NewFileRootCAFetcher.
// If there's cache, returns cache.
func (f *FileRootCAFetcher) Fetch(context.Context) ([][]byte, error) {
	if f.rootCA != nil {
		return f.rootCA, nil
	}
	for _, path := range f.paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return f.rootCA, err
		}
		dbuf := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
		base64.StdEncoding.Encode(dbuf, b)
		f.rootCA = append(f.rootCA, dbuf)
	}
	return f.rootCA, nil
}

// RawRootCAFetcher implements RootCAFetcher via raw bytes.
type RawRootCAFetcher struct {
	rootCA [][]byte
}

// NewRawRootCAFetcher returns a new RawRootCAFetcher.
// At least one certificate must be set as a byte string.
// Optional byte slice argument is for setting multiple Root CAs.
func NewRawRootCAFetcher(rootCA []byte, optional ...[]byte) *RawRootCAFetcher {
	return &RawRootCAFetcher{rootCA: append([][]byte{rootCA}, optional...)}
}

// Fetch returns the Root CAs set by NewRawRootCAFetcher.
func (f *RawRootCAFetcher) Fetch(context.Context) ([][]byte, error) {
	return f.rootCA, nil
}
