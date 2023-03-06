package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default timeout values
const DefaultReqTimeoutVal int = 100
const DefaultBackoffMinDelay int = 4
const DefaultBackoffMaxDelay int = 60
const DefaultBackoffDelayFactor float64 = 3

// Client is the main entry point
type Client struct {
	BaseURL            *url.URL
	httpClient         *http.Client
	username           string
	password           string
	insecure           bool
	reqTimeoutSet      bool
	reqTimeoutVal      uint32
	proxyUrl           string
	proxyCreds         string
	skipLoggingPayload bool
	maxRetries         int
	backoffMinDelay    int
	backoffMaxDelay    int
	backoffDelayFactor float64
}

// singleton implementation of a client
var clientImpl *Client

type Option func(*Client)

func Insecure(insecure bool) Option {
	return func(client *Client) {
		client.insecure = insecure
	}
}

func ProxyUrl(pUrl string) Option {
	return func(client *Client) {
		client.proxyUrl = pUrl
	}
}

func ProxyCreds(pcreds string) Option {
	return func(client *Client) {
		client.proxyCreds = pcreds
	}
}

func MaxRetries(maxRetries int) Option {
	return func(client *Client) {
		client.maxRetries = maxRetries
	}
}

func BackoffMinDelay(backoffMinDelay int) Option {
	return func(client *Client) {
		client.backoffMinDelay = backoffMinDelay
	}
}

func BackoffMaxDelay(backoffMaxDelay int) Option {
	return func(client *Client) {
		client.backoffMaxDelay = backoffMaxDelay
	}
}

func BackoffDelayFactor(backoffDelayFactor float64) Option {
	return func(client *Client) {
		client.backoffDelayFactor = backoffDelayFactor
	}
}

// HttpClient option: allows for caller to set 'httpClient' with 'Transport'.
// When this option is set 'client.proxyUrl' option is ignored.
func HttpClient(httpcl *http.Client) Option {
	return func(client *Client) {
		client.httpClient = httpcl
	}
}

func SkipLoggingPayload(skipLoggingPayload bool) Option {
	return func(client *Client) {
		client.skipLoggingPayload = skipLoggingPayload
	}
}

func ReqTimeout(timeout uint32) Option {
	return func(client *Client) {
		client.reqTimeoutSet = true
		client.reqTimeoutVal = timeout
	}
}

func initClient(clientUrl, username string, password string, options ...Option) *Client {
	var transport *http.Transport
	bUrl, err := url.Parse(clientUrl)

	if err != nil {
		// cannot move forward if url is undefined
		log.Fatal(err)
	}

	authClientUrl := bUrl.Scheme + "://" + username + ":" + password + "@" + bUrl.Host + bUrl.Path
	rUrl, err := url.Parse(authClientUrl)

	if err != nil {
		// cannot move forward if url is undefined
		log.Fatal(err)
	}
	client := &Client{
		BaseURL:  rUrl,
		username: username,
		password: password,
	}

	for _, option := range options {
		option(client)
	}

	if client.httpClient == nil {
		transport = client.useInsecureHTTPClient(client.insecure)
		if client.proxyUrl != "" {
			transport = client.configProxy(transport)
		}
		client.httpClient = &http.Client{
			Transport: transport,
		}
	}

	var timeout time.Duration
	if client.reqTimeoutSet {
		timeout = time.Second * time.Duration(client.reqTimeoutVal)
	} else {
		timeout = time.Second * time.Duration(DefaultReqTimeoutVal)
	}

	client.httpClient.Timeout = timeout
	return client
}

// GetClient returns a singleton
func GetClient(clientUrl, username string, password string, options ...Option) *Client {
	if clientImpl == nil {
		clientImpl = initClient(clientUrl, username, password, options...)
	} else {
		// making sure it is the same client
		bUrl, err := url.Parse(clientUrl)
		if err != nil {
			// cannot move forward if url is undefined
			log.Fatal(err)
		}
		if bUrl != clientImpl.BaseURL {
			clientImpl = initClient(clientUrl, username, password, options...)
		}
	}
	return clientImpl
}

// NewClient returns a new Instance of the client
func NewClient(clientUrl, username string, password string, options ...Option) *Client {
	// making sure it is the same client
	_, err := url.Parse(clientUrl)
	if err != nil {
		// cannot move forward if url is undefined
		log.Fatal(err)
	}

	// initClient always returns a new struct, so always create a new pointer to allow for
	// multiple object instances
	newClientImpl := initClient(clientUrl, username, password, options...)

	return newClientImpl
}

func (c *Client) configProxy(transport *http.Transport) *http.Transport {
	log.Printf("[DEBUG]: Using Proxy Server: %s ", c.proxyUrl)
	pUrl, err := url.Parse(c.proxyUrl)
	if err != nil {
		log.Fatal(err)
	}
	transport.Proxy = http.ProxyURL(pUrl)

	if c.proxyCreds != "" {
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.proxyCreds))
		transport.ProxyConnectHeader = http.Header{}
		transport.ProxyConnectHeader.Add("Proxy-Authorization", basicAuth)
	}
	return transport
}

func (c *Client) useInsecureHTTPClient(insecure bool) *http.Transport {
	// proxyUrl, _ := url.Parse("http://10.0.1.167:3128")

	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
		InsecureSkipVerify:       insecure,
		MinVersion:               tls.VersionTLS11,
		MaxVersion:               tls.VersionTLS13,
	}

	return transport

}

// Takes raw payload and does the http request
func (c *Client) MakeXMLRPCRequestRaw(payload []byte) (*http.Request, error) {
	var req *http.Request
	method := "POST"
	bUrl, _ := url.Parse(c.BaseURL.String())

	req, err := http.NewRequest(method, c.BaseURL.String(), bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	if c.skipLoggingPayload {
		log.Printf("HTTP request %s %s %s %s", method, bUrl.Scheme, bUrl.Host, bUrl.Path)
	} else {
		log.Printf("HTTP request %s %s %s %s %v", method, bUrl.Scheme, bUrl.Host, bUrl.Path, req)
	}

	return req, nil
}

func StrtoInt(s string, startIndex int, bitSize int) (int64, error) {
	return strconv.ParseInt(s, startIndex, bitSize)
}

func (c *Client) DoRaw(req *http.Request) (*http.Response, error) {
	bUrl, _ := url.Parse(c.BaseURL.String())

	log.Printf("[DEBUG] Begining DoRaw method %s %s", bUrl.Host, bUrl.Path)

	// retain the request body across multiple attempts
	var body []byte
	if req.Body != nil && c.maxRetries != 0 {
		body, _ = ioutil.ReadAll(req.Body)
	}

	for attempts := 0; ; attempts++ {
		log.Printf("[TRACE] HTTP Request Method and URL: %s %s %s %s", req.Method, bUrl.Scheme, bUrl.Host, bUrl.Path)
		if c.maxRetries != 0 {
			req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		}
		if !c.skipLoggingPayload {
			log.Printf("[TRACE] HTTP Request Body: %v", req.Body)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ok := c.backoff(attempts); !ok {
				log.Printf("[ERROR] HTTP Connection error occured: %+v", err)
				log.Printf("[DEBUG] Exit from DoRaw method")
				return nil, errors.New(fmt.Sprintf("Failed to connect to Pfsense. Verify that you are connecting to an Pfsense.\nError message: %+v", err))
			} else {
				log.Printf("[ERROR] HTTP Connection failed: %s, retries: %v", err, attempts)
				continue
			}
		}

		if !c.skipLoggingPayload {
			log.Printf("[TRACE] HTTP Response: %d %s %v", resp.StatusCode, resp.Status, resp)
		} else {
			log.Printf("[TRACE] HTTP Response: %d %s", resp.StatusCode, resp.Status)
		}

		if (resp.StatusCode < 500 || resp.StatusCode > 504) && resp.StatusCode != 405 {
			log.Printf("[DEBUG] Exit from DoRaw method")
			return resp, nil
		} else {
			if ok := c.backoff(attempts); !ok {
				log.Printf("[DEBUG] Exit from DoRaw method")
				return resp, nil
			} else {
				log.Printf("[ERROR] HTTP Request failed: StatusCode %v, Retries: %v", resp.StatusCode, attempts)
				continue
			}
		}
	}
}

func stripQuotes(word string) string {
	if strings.HasPrefix(word, "\"") && strings.HasSuffix(word, "\"") {
		return strings.TrimSuffix(strings.TrimPrefix(word, "\""), "\"")
	}
	return word
}

func (c *Client) backoff(attempts int) bool {
	log.Printf("[DEBUG] Begining backoff method: attempts %v on %v", attempts, c.maxRetries)
	if attempts >= c.maxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	minDelay := time.Duration(DefaultBackoffMinDelay) * time.Second
	if c.backoffMinDelay != 0 {
		minDelay = time.Duration(c.backoffMinDelay) * time.Second
	}

	maxDelay := time.Duration(DefaultBackoffMaxDelay) * time.Second
	if c.backoffMaxDelay != 0 {
		maxDelay = time.Duration(c.backoffMaxDelay) * time.Second
	}

	factor := DefaultBackoffDelayFactor
	if c.backoffDelayFactor != 0 {
		factor = c.backoffDelayFactor
	}

	min := float64(minDelay)
	backoff := min * math.Pow(factor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))
	time.Sleep(backoffDuration)
	log.Printf("[DEBUG] Exit from backoff method with return value true")
	return true
}
