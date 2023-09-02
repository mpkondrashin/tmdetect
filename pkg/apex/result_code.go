package apex

import "fmt"

type ResultCode int

const (
	OperationSuccessful                                   ResultCode = 1
	SuspiciousObjectActionFailedDueToATSEEngineError      ResultCode = -1102
	SuspiciousObjectActionFailedDueToExceedSOMaximum      ResultCode = -1101
	ServerActionFailedDueToTargetServerNotSupportAction   ResultCode = -207
	ServerActionFailedDueToTargetServerNotFound           ResultCode = -205
	ServerActionFailedDueToTemporaryRemoteServerErrors    ResultCode = -204
	ServerActionFailedDueToTargetServerIsCascadingServers ResultCode = -203
	ServerActionFailedDueToMultipleMatches                ResultCode = -202
	AgentActionFailedDueToTargetServerNotSupportAction    ResultCode = -107
	AgentActionFailedDueToTargetServerIsCasdingServer     ResultCode = -106
	AgentActionFailedDueToTargetServerNotFound            ResultCode = -105
	AgentActionFailedDueToTemporaryRemoteServerErrors     ResultCode = -104
	AgentActionFailedDueToCascadingAgents                 ResultCode = -103
	AgentActionFailedDueToMultipleMatches                 ResultCode = -102
	InternalServerError                                   ResultCode = -99
	UnSupportedHTTPMethod                                 ResultCode = -50
	InvalidAct                                            ResultCode = -22
	InvalidInputParameters                                ResultCode = -21
	AuthenticationFailureUnsupportedTokenHashFunction     ResultCode = -9
	AuthenticationFailureInvalidRequestCheckSum           ResultCode = -8
	AuthenticationFailureInvalidTokenSignature            ResultCode = -7
	AuthenticationFailureTokenExpired                     ResultCode = -6
	AuthenticationFailureInvalidApplicationID             ResultCode = -5
	AuthenticationFailureUnSupportedTokenVersion          ResultCode = -4
	AuthenticationFailureMalformedToken                   ResultCode = -3
	AuthenticationFailureTokenNotProvided                 ResultCode = -2
)

var MapToString = map[ResultCode]string{
	OperationSuccessful: "Operation Successful",
	SuspiciousObjectActionFailedDueToATSEEngineError:      "Suspicious Object Action Failed Due To ATSE Engine Error",
	SuspiciousObjectActionFailedDueToExceedSOMaximum:      "Suspicious Object Action Failed Due To Exceed SO Maximum",
	ServerActionFailedDueToTargetServerNotSupportAction:   "Server Action Failed Due To Target Server Not Support Action",
	ServerActionFailedDueToTargetServerNotFound:           "Server Action Failed Due To Target Server Not Found",
	ServerActionFailedDueToTemporaryRemoteServerErrors:    "Server Action Failed Due To Temporary Remote Server Errors",
	ServerActionFailedDueToTargetServerIsCascadingServers: "Server Action Failed Due To Target Server Is Cascading Servers",
	ServerActionFailedDueToMultipleMatches:                "Server Action Failed Due To Multiple Matches",
	AgentActionFailedDueToTargetServerNotSupportAction:    "Agent Action Failed Due To Target Server Not Support Action",
	AgentActionFailedDueToTargetServerIsCasdingServer:     "Agent Action Failed Due To Target Server Is Casding Server",
	AgentActionFailedDueToTargetServerNotFound:            "Agent Action Failed Due To Target Server Not Found",
	AgentActionFailedDueToTemporaryRemoteServerErrors:     "Agent Action Failed Due To Temporary Remote Server Errors",
	AgentActionFailedDueToCascadingAgents:                 "Agent Action Failed Due To Cascading Agents",
	AgentActionFailedDueToMultipleMatches:                 "Agent Action Failed Due To Multiple Matches",
	InternalServerError:                                   "Internal ServerError",
	UnSupportedHTTPMethod:                                 "UnSupported HTTP Method",
	InvalidAct:                                            "Invalid Act",
	InvalidInputParameters:                                "Invalid Input Parameters",
	AuthenticationFailureUnsupportedTokenHashFunction:     "Authentication Failure Unsupported Token Hash Function",
	AuthenticationFailureInvalidRequestCheckSum:           "Authentication Failure Invalid Request CheckSum",
	AuthenticationFailureInvalidTokenSignature:            "Authentication Failure Invalid Token Signature",
	AuthenticationFailureTokenExpired:                     "Authentication Failure Token Expired",
	AuthenticationFailureInvalidApplicationID:             "Authentication Failure Invalid Application ID",
	AuthenticationFailureUnSupportedTokenVersion:          "Authentication Failure UnSupported Token Version",
	AuthenticationFailureMalformedToken:                   "Authentication Failure Malformed Token",
	AuthenticationFailureTokenNotProvided:                 "Authentication Failure Token Not Provided",
}

func (code ResultCode) String() string {
	result, ok := MapToString[code]
	if !ok {
		return fmt.Sprintf("unknown error %d", code)
	}
	return result
}
