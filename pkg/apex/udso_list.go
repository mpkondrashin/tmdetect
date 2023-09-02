package apex

import (
	"context"
	"errors"
	"fmt"
)

/*
type UDSOListResponse struct {
	Data []struct {
		Type              string `json:"type"`
		Content           string `json:"content"`
		Notes             string `json:"notes"`
		ScanAction        string `json:"scan_action"`
		ExpirationUtcDate string `json:"expiration_utc_date"`
	} `json:"Data"`
	Meta struct {
		Result    int    `json:"Result"`
		ErrorCode int    `json:"ErrorCode"`
		ErrorMsg  string `json:"ErrorMsg"`
	} `json:"Meta"`
	PermissionCtrl struct {
		Permission string `json:"permission"`
		Elements   any    `json:"elements"`
	} `json:"PermissionCtrl"`
	FeatureCtrl struct {
		Mode string `json:"mode"`
	} `json:"FeatureCtrl"`
	SystemCtrl struct {
		TmcmSoDistRole string `json:"TmcmSoDist_Role"`
	} `json:"SystemCtrl"`
}

func (c *Central) UDSOList001(ctx context.Context, udsoType UDSOType, filter string) (*UDSOListResponse, error) {
	path := "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
	query := fmt.Sprintf("?type=%s", udsoType)
	log.Println(query)
	if filter != "" {
		query += "&contentFilter=" + filter
	}
	response := new(UDSOListResponse)
	err := c.call(ctx, "GET", path, query, "", response)
	if err != nil {
		return nil, err
	}
	return response, err
}
*/

type (
	UDSOListItem struct {
		Type              UDSOType          `json:"type"`
		Content           string            `json:"content"`
		Notes             string            `json:"notes"`
		ScanAction        ScanAction        `json:"scan_action"`
		ExpirationUtcDate ExpirationUTCDate `json:"expiration_utc_date"`
	}

	UDSOListData []UDSOListItem

	UDSOListRequest struct {
		Request
		Response UDSOListData
	}
)

func (c *Central) UDSOList(udsoType UDSOType) *UDSOListRequest {
	r := UDSOListRequest{
		Request: Request{
			Central: c,
			Method:  "GET",
			Path:    "/WebApp/api/SuspiciousObjects/UserDefinedSO/",
			Query:   fmt.Sprintf("?type=%s", udsoType),
			Body:    "",
		},
		Response: UDSOListData{},
	}
	r.Request.Response = ApexResponse{
		Data: &r.Response,
	}
	return &r
}

var ErrWrongType = errors.New("wrong type")

func (r *UDSOListRequest) SetFilter(filter string) *UDSOListRequest {
	r.Query += "&contentFilter=" + filter
	return r
}

func (r *UDSOListRequest) Do(ctx context.Context) (UDSOListData, error) {
	err := r.Request.Do(ctx)
	if err != nil {
		return nil, err
	}
	return r.Response, nil
}

/*
func (c *Central) UDSOList___(ctx context.Context, udsoType UDSOType, filter string) (*UDSOListResponse, error) {
	path := "/WebApp/api/SuspiciousObjects/UserDefinedSO/"
	query := fmt.Sprintf("?type=%s", udsoType)
	log.Println(query)
	if filter != "" {
		query += "&contentFilter=" + filter
	}
	response := new(UDSOListResponse)
	err := c.call(ctx, "GET", path, query, "", response)
	if err != nil {
		return nil, err
	}
	return response, err
}
*/
