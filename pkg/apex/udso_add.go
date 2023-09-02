package apex

import (
	"context"
	"encoding/json"
	"time"
)

/*
type UDSOAddParam struct {
	Content           string     `json:"content"`
	ExpirationUtcDate time.Time  `json:"expiration_utc_date"`
	Notes             string     `json:"notes"`
	ScanAction        ScanAction `json:"scan_action"`
	Type              UDSOType   `json:"type"`
}*/

type UDSOAddRequestJSON struct {
	Param UDSOListItem `json:"param"`
}

type UDSOAddRequest struct {
	Request
	Response UDSOListItem
}

/*
	type UDSOAddResponse struct {
		Data        string `json:"Data"`
		FeatureCtrl struct {
			Mode string `json:"mode"`
		} `json:"FeatureCtrl"`
		Meta struct {
			ErrorCode int    `json:"ErrorCode"`
			ErrorMsg  string `json:"ErrorMsg"`
			Result    int    `json:"Result"`
		} `json:"Meta"`
		PermissionCtrl struct {
			Elements   string `json:"elements"`
			Permission string `json:"permission"`
		} `json:"PermissionCtrl"`
		SystemCtrl struct {
			TmcmSoDistRole string `json:"TmcmSoDist_Role"`
		} `json:"SystemCtrl"`
	}
*/

func (c *Central) UDSOAddParam(p *UDSOListItem) *UDSOAddRequest {
	request := UDSOAddRequestJSON{
		Param: *p,
	}
	//data, err := json.MarshalIndent(&request, "", " ")
	body, _ := json.Marshal(&request)
	r := UDSOAddRequest{
		Request: Request{
			Central: c,
			Method:  "PUT",
			Path:    "/WebApp/api/SuspiciousObjects/UserDefinedSO/",
			Query:   "",
			Body:    string(body),
		},
		//Response: UDSOListData{},
	}
	r.Request.Response = ApexResponse{
		Data: "",
	}
	return &r
}

func (c *Central) UDSOAdd(udsoType UDSOType, content string, scanAction ScanAction, expiration time.Time, notes string) *UDSOAddRequest {
	return c.UDSOAddParam(&UDSOListItem{
		Content:           content,
		ExpirationUtcDate: ExpirationUTCDate(expiration),
		Notes:             notes,
		ScanAction:        scanAction,
		Type:              udsoType,
	},
	)
}

func (r *UDSOAddRequest) Do(ctx context.Context) error {
	return r.Request.Do(ctx)
}

/*
func (c *Central) UDSOAdd(ctx context.Context,
	udsoType UDSOType,
	content string,
	notes string,
	scan_action ScanAction,
	expiration_utc_date time.Time) error { //(*UDSOListResponse, error) {
	path := "/WebApp/api/SuspiciousObjects/UserDefinedSO/"

	request := UDSOAddRequestJSON{
		Param: UDSOAddParam{
			Content:           content,
			ExpirationUtcDate: time.Date(2024, 1, 1, 1, 1, 1, 0, time.UTC), //////expiration_utc_date,
			Notes:             notes,
			ScanAction:        scan_action,
			Type:              udsoType,
		},
	}
	//data, err := json.MarshalIndent(&request, "", " ")
	data, err := json.Marshal(&request)
	if err != nil {
		return err
	}

	log.Print(string(data))
	response := new(UDSOAddResponse)
	if err := c.call(ctx, "PUT", path, "", string(data), response); err != nil {
		return err
	}
	log.Println(response)
	return nil
}
*/
