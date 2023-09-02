package apex

import (
	"context"
	"net/http"
)

type ListSecurityAgentsV2Response struct {
	ResultCode    ResultCode `json:"result_code"`
	ResultContent []struct {
		EndpointID            string   `json:"endpointID"`
		EndpointHost          string   `json:"endpointHost"`
		EndpointIP            string   `json:"endpointIP"`
		EndpointMAC           string   `json:"endpointMAC"`
		Product               string   `json:"product"`
		ManagingServerID      string   `json:"managingServerID"`
		AdDomain              string   `json:"adDomain"`
		Domain                string   `json:"domain"`
		DomainHierarchy       string   `json:"domainHierarchy"`
		LogonUser             string   `json:"logonUser"`
		Platform              string   `json:"platform"`
		ClientProgram         string   `json:"clientProgram"`
		ConnectionStatus      string   `json:"connectionStatus"`
		IsolationStatus       string   `json:"isolationStatus"`
		Firewall              string   `json:"firewall"`
		ScanMethod            string   `json:"scanMethod"`
		UpdateAgent           string   `json:"updateAgent"`
		LastScheduledScanUTC  string   `json:"lastScheduledScanUTC"`
		LastManualScanUTC     string   `json:"lastManualScanUTC"`
		LastStartup           string   `json:"lastStartup"`
		LastConnected         string   `json:"lastConnected"`
		VirusScanEngine       string   `json:"virusScanEngine"`
		VirusPattern          string   `json:"virusPattern"`
		SmartScanAgentPattern string   `json:"smartScanAgentPattern"`
		Capabilities          []string `json:"capabilities"`
	} `json:"result_content"`
	ResultDescription string `json:"result_description"`
}

type ListSecurityAgentsV1Response struct {
	ResultCode        int    `json:"result_code"`
	ResultDescription string `json:"result_description"`
	ResultContent     []struct {
		EntityID         string   `json:"entity_id"`
		Product          string   `json:"product"`
		ManagingServerID string   `json:"managing_server_id"`
		AdDomain         string   `json:"ad_domain"`
		FolderPath       string   `json:"folder_path"`
		IPAddressList    string   `json:"ip_address_list"`
		MacAddressList   string   `json:"mac_address_list"`
		HostName         string   `json:"host_name"`
		IsolationStatus  string   `json:"isolation_status"`
		Capabilities     []string `json:"capabilities"`
	} `json:"result_content"`
}

type SecurityAgentsListQuery struct {
	entityID         string // The GUID of the Security Agent
	ipAddress        string // The IP address of the endpoint
	macAddress       string // The MAC address of the endpoint
	hostName         string // The name of the endpoint
	product          string // The Trend Micro product ID. For example: 15 = Apex One, 31001 = Apex One(Mac)
	managingServerID string // The GUID of the product server that manages the Security Agent
}

func (s *SecurityAgentsListQuery) Query() string {
	req, _ := http.NewRequest("GET", "http://www/", nil)
	q := req.URL.Query()
	if s.entityID != "" {
		q.Add("entityID", s.entityID)
	}
	if s.ipAddress != "" {
		q.Add("ipAddress", s.ipAddress)
	}
	if s.macAddress != "" {
		q.Add("macAddress", s.macAddress)
	}
	if s.hostName != "" {
		q.Add("hostName", s.hostName)
	}
	if s.product != "" {
		q.Add("product", s.product)
	}
	if s.managingServerID != "" {
		q.Add("managingServerID", s.managingServerID)
	}
	req.URL.RawQuery = q.Encode()
	return req.URL.String()
}

func (c *Central) ListSecurityAgentsV2(ctx context.Context, query *SecurityAgentsListQuery) (*ListSecurityAgentsV2Response, error) {
	path := "/WebApp/API/v2/AgentResource/ProductAgents"
	//	useQueryString := "?ipAddress=192.168.8.145" //# ?ipAddress=192.168.121.132&macAddress=00-0C-29-9B-AB-65&hostName=OSCECLIENT"
	result := new(ListSecurityAgentsV2Response)
	q := ""
	if query != nil {
		q = query.Query()
	}
	err := c.call(ctx, "GET", path, q, "", result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Central) ListSecurityAgentsV1(ctx context.Context, query *SecurityAgentsListQuery) (*ListSecurityAgentsV1Response, error) {
	path := "/WebApp/API/v1/AgentResource/ProductAgents"
	//	useQueryString := "?ipAddress=192.168.8.145" //# ?ipAddress=192.168.121.132&macAddress=00-0C-29-9B-AB-65&hostName=OSCECLIENT"
	result := new(ListSecurityAgentsV1Response)
	q := ""
	if query != nil {
		q = query.Query()
	}
	err := c.call(ctx, "GET", path, q, "", result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
