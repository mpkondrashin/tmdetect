package apex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const Version = "V1"

const (
	Failed  = 0
	Success = 1
)

type Central struct {
	address        string
	applicationID  string
	apiKey         string
	ignoreTLSError bool
	proxy          string
}

func NewCentral(address string, applicationID string, apiKey string) *Central {
	return &Central{
		address:       address,
		applicationID: applicationID,
		apiKey:        apiKey,
	}
}

func (c *Central) SetIgnoreTLSError(ignoreTLSError bool) *Central {
	c.ignoreTLSError = ignoreTLSError
	return c
}

func (c *Central) SetProxy(proxy string) *Central {
	c.proxy = proxy
	return c
}

func (c *Central) call(ctx context.Context, method string, path string, query string, body string, result any) error {
	canonicalRequestHeaders := ""
	jwtToken, err := c.CreateJWTToken(method, path+query, canonicalRequestHeaders, body)
	if err != nil {
		return fmt.Errorf("CreateJWTToken: %w", err)
	}
	uri := c.address + path + query
	req, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.ignoreTLSError},
	}
	if c.proxy != "" {
		proxyURL, err := url.Parse(c.proxy)
		if err != nil {
			return fmt.Errorf("proxy error: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Transport: transport}

	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	//io.Copy(os.Stdout, resp.Body)
	return json.NewDecoder(response.Body).Decode(result)
}

// PUT|/webapp/api/suspiciousobjects/userdefinedso/||{"param":{"content":"A6CE7DE67AEB35871EAF763001AB7DA799B43E52","expiration_utc_date":"2023-08-13T19:06:07.915215+03:00","notes":"note1","scan_action":"log","type":2}}
func (c *Central) CreateChecksum(httpMethod string, rawURL string, headers string, request_body string) string {
	string_to_hash := strings.ToUpper(httpMethod) + "|" + strings.ToLower(rawURL) + "|" + headers + "|" + request_body
	hash := sha256.New()
	hash.Write([]byte(string_to_hash))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func (c *Central) CreateJWTToken(httpMethod string, rawURL string, headers string, requestBody string) (string, error) {
	claims := jwt.MapClaims{
		"appid":    c.applicationID,
		"iat":      time.Now().Unix(),
		"version":  Version,
		"checksum": c.CreateChecksum(httpMethod, rawURL, headers, requestBody),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.apiKey))
}

type Request struct {
	Central  *Central
	Method   string
	Path     string
	Query    string
	Body     string
	Response ApexResponse
}

type ErrApex struct {
	Result    int    `json:"Result"`
	ErrorCode int    `json:"ErrorCode"`
	ErrorMsg  string `json:"ErrorMsg"`
}

func (e *ErrApex) Error() string {
	return fmt.Sprintf("Error %d (%s)", e.ErrorCode, e.ErrorMsg)
}

type ApexResponse struct {
	Data           any
	Meta           ErrApex `json:"Meta"`
	PermissionCtrl struct {
		Permission Permission `json:"permission"`
		Elements   any        `json:"elements"`
	} `json:"PermissionCtrl"`
	FeatureCtrl struct {
		Mode Mode `json:"mode"`
	} `json:"FeatureCtrl"`
	SystemCtrl struct {
		TmcmSoDistRole SoDistRole `json:"TmcmSoDist_Role"`
	} `json:"SystemCtrl"`
}

func (r *Request) Do(ctx context.Context) error {
	canonicalRequestHeaders := ""
	jwtToken, err := r.Central.CreateJWTToken(r.Method, r.Path+r.Query, canonicalRequestHeaders, r.Body)
	if err != nil {
		return fmt.Errorf("CreateJWTToken: %w", err)
	}
	uri := r.Central.address + r.Path + r.Query
	var requestBodyReader io.Reader
	if r.Body != "" {
		requestBodyReader = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, uri, requestBodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: r.Central.ignoreTLSError},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	var body bytes.Buffer
	if _, err := io.Copy(&body, resp.Body); err != nil {
		return err
	}
	var errorResponse ApexResponse
	if err := json.Unmarshal(body.Bytes(), &errorResponse); err != nil {
		return fmt.Errorf("%s: %w", body.String(), err)
	}
	if errorResponse.Meta.Result == Failed {
		return &errorResponse.Meta
	}
	if err := json.Unmarshal(body.Bytes(), &r.Response); err != nil {
		return fmt.Errorf("%s: %w", body.String(), err)
	}
	return nil
}
