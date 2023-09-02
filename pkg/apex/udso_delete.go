package apex

import (
	"context"
	"fmt"
	"time"
)

type UDSODeleteData []struct {
	Type              string     `json:"type"`
	Content           string     `json:"content"`
	Notes             string     `json:"notes"`
	ScanAction        ScanAction `json:"scan_action"`
	ExpirationUtcDate string     `json:"expiration_utc_date"`
}

type UDSODeleteRequest struct {
	Request
}

func (c *Central) UDSODelete() *UDSODeleteRequest {
	return &UDSODeleteRequest{
		Request{
			Central: c,
			Method:  "DELETE",
			Path:    "/WebApp/api/SuspiciousObjects/UserDefinedSO/",
			Query:   "",
			Body:    "",
			Response: ApexResponse{
				Data: "", //new(UDSODeleteData),
			},
		},
	}
}

func (r *UDSODeleteRequest) AddQueryParameter(name, value string) {
	if r.Query == "" {
		r.Query += fmt.Sprintf("?%s=%s", name, value)
	} else {
		r.Query += fmt.Sprintf("&%s=%s", name, value)
	}
}

func (r *UDSODeleteRequest) SetType(udsoType UDSOType) *UDSODeleteRequest {
	r.AddQueryParameter("type", udsoType.String())
	return r
}

func (r *UDSODeleteRequest) SetContent(content string) *UDSODeleteRequest {
	r.AddQueryParameter("content", content)
	return r
}

func (r *UDSODeleteRequest) SetNote(notes string) *UDSODeleteRequest {
	r.AddQueryParameter("notes", notes)
	return r
}
func (r *UDSODeleteRequest) SetScanAction(scanAction string) *UDSODeleteRequest {
	r.AddQueryParameter("scan_action", scanAction)
	return r
}

func (r *UDSODeleteRequest) SetExpirationDate(expirationUTCDate time.Time) *UDSODeleteRequest {
	r.AddQueryParameter("expiration_utc_date", expirationUTCDate.String())
	return r
}

func (r *UDSODeleteRequest) Do(ctx context.Context) (UDSODeleteData, error) {
	err := r.Request.Do(ctx)
	if err != nil {
		return nil, err
	}
	return nil, nil
	/*data, ok := r.Response.Data.(*UDSODeleteData)
	if !ok {
		return nil, ErrWrongType
	}
	return *data, nil*/
}

/*
func (c *Central) UDSOLis_(udsoType UDSOType, filter string) (*UDSOListResponse, error) {
	productAgentAPIPath := "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
	canonicalRequestHeaders := ""
	useRequestBody := ""

	query := fmt.Sprintf("?type=%s", udsoType)
	log.Println(query)
	if filter != "" {
		query += "&contentFilter=" + filter
	}
	jwtToken, err := CreateJWTToken(c.applicationID, c.apiKey, "GET",
		productAgentAPIPath+query,
		canonicalRequestHeaders, useRequestBody, time.Now(), "HS256", "V1")
	if err != nil {
		return nil, fmt.Errorf("CreateJWTToken: %w", err)
	}
	ctx := context.TODO()
	uri := c.address + path + query
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	io.Copy(os.Stdout, resp.Body)

	result := new(UDSOListResponse)
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return nil, err
	}
	return result, nil

}
*/
