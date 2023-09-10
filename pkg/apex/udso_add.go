package apex

import (
	"context"
	"encoding/json"
	"time"
)

type UDSOAddRequestJSON struct {
	Param UDSOListItem `json:"param"`
}

type UDSOAddRequest struct {
	Request
	Response UDSOListItem
}

func (c *Central) UDSOAddParam(p *UDSOListItem) *UDSOAddRequest {
	request := UDSOAddRequestJSON{
		Param: *p,
	}
	body, _ := json.Marshal(&request)
	r := UDSOAddRequest{
		Request: Request{
			Central: c,
			Method:  "PUT",
			Path:    "/WebApp/api/SuspiciousObjects/UserDefinedSO/",
			Query:   "",
			Body:    string(body),
		},
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
