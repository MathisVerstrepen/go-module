package webfetch

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type Header map[string]string
type Param map[string]string

type FetcherParams struct {
	Method       string
	Url          string
	Body         any
	Headers      Header
	Params       Param
	UseProxy     bool
	WantErrCodes []int
}

type FetcherClient interface {
	FetchData(fp FetcherParams) []byte
}

type Fetcher struct {
	ProxyUrl      string
	ProxyUsername string
	ProxyPassword string
	Verbose       bool
}

func InitFetchers(basepath string) *[]Fetcher {
	data, err := os.ReadFile(filepath.Join(basepath, "/proxies.txt"))

	if err != nil {
		log.Printf("From %s", basepath)
		log.Printf("%v", err)
		log.Fatal("Failed to read proxies file")
	}

	lines := strings.Split(string(data), "\n")
	num_proxies := len(lines)

	if lines[num_proxies-1] == "" {
		num_proxies -= 1
	}

	fetchers := make([]Fetcher, num_proxies)

	for index, line := range lines[:num_proxies] {
		args := strings.Split(string(line), ":")

		if len(args) != 4 {
			log.Fatal("Fail to parse proxies file line")
		}

		fetchers[index] = Fetcher{
			ProxyUrl:      args[0] + ":" + args[1],
			ProxyUsername: args[2],
			ProxyPassword: args[3],
			Verbose:       false,
		}
	}

	return &fetchers
}

func (f Fetcher) FetchData(fp FetcherParams) []byte {
	client := &http.Client{}

	if fp.UseProxy {
		auth := proxy.Auth{User: f.ProxyUsername, Password: f.ProxyPassword}
		dialer, err := proxy.SOCKS5("tcp", f.ProxyUrl, &auth, &net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			log.Fatalf("Failed to initialize proxy.\nErr : %s", err)
		}

		dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
		transport := &http.Transport{DialContext: dialContext,
			DisableKeepAlives: true}
		client = &http.Client{Transport: transport}
	}

	baseUrl, err := url.Parse(fp.Url)
	if err != nil {
		log.Fatalf("Failed to parse url.\nErr : %s", err)
	}

	params := url.Values{}
	for paramKey, paramValue := range fp.Params {
		params.Add(paramKey, paramValue)
	}
	baseUrl.RawQuery = params.Encode()

	var bodyBuffer *bytes.Buffer = &bytes.Buffer{}
	if fp.Body != nil {
		jsonBytes, err := json.Marshal(fp.Body)
		if err != nil {
			log.Fatalf("Failed to encode req body in bytes.\nErr : %s", err)
		}
		bodyBuffer = bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest(fp.Method, baseUrl.String(), bodyBuffer)
	if err != nil {
		log.Fatalf("Failed to initialize request.\nErr : %s", err)
	}

	for headerKey, headerValue := range fp.Headers {
		req.Header.Set(headerKey, headerValue)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to make request.\nErr : %s", err)
	}

	if fp.WantErrCodes == nil && resp.StatusCode != 200 {
		log.Fatalf("Got status code %d instead of wanted 200\nUrl : %s", resp.StatusCode, fp.Url)
	} else if fp.WantErrCodes != nil && !slices.Contains(fp.WantErrCodes, resp.StatusCode) {
		log.Fatalf("Got status code %d instead of wanted %d\nUrl : %s", resp.StatusCode, fp.WantErrCodes, fp.Url)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read body from request response.\nErr : %s", err)
	}

	return body
}
