// Code generated by enum (github.com/mpkondrashin/enum) using following command:
// enum -package apex -type UDSOType -names ip,url,file_sha1,domain,file
// DO NOT EDIT!

package apex

import (
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "strings"
)

type UDSOType int

const (
    UDSOTypeIp        UDSOType = iota
    UDSOTypeUrl       UDSOType = iota
    UDSOTypeFile_sha1 UDSOType = iota
    UDSOTypeDomain    UDSOType = iota
    UDSOTypeFile      UDSOType = iota
)


// String - return string representation for UDSOType value
func (v UDSOType)String() string {
    s, ok := map[UDSOType]string {
         UDSOTypeIp:        "ip",
         UDSOTypeUrl:       "url",
         UDSOTypeFile_sha1: "file_sha1",
         UDSOTypeDomain:    "domain",
         UDSOTypeFile:      "file",
    }[v]
    if ok {
        return s
    }
    return "UDSOType(" + strconv.FormatInt(int64(v), 10) + ")"
}

// ErrUnknownUDSOType - will be returned wrapped when parsing string
// containing unrecognized value.
var ErrUnknownUDSOType = errors.New("unknown UDSOType")


var mapUDSOTypeFromString = map[string]UDSOType{
    "ip":    UDSOTypeIp,
    "url":    UDSOTypeUrl,
    "file_sha1":    UDSOTypeFile_sha1,
    "domain":    UDSOTypeDomain,
    "file":    UDSOTypeFile,
}

// UnmarshalJSON implements the Unmarshaler interface of the json package for UDSOType.
func (s *UDSOType) UnmarshalJSON(data []byte) error {
    var v string
    if err := json.Unmarshal(data, &v); err != nil {
        return err
    }
    result, ok := mapUDSOTypeFromString[strings.ToLower(v)]
    if !ok {
        return fmt.Errorf("%w: %s", ErrUnknownUDSOType, v)
    }
    *s = result
    return nil
}

// MarshalJSON implements the Marshaler interface of the json package for UDSOType.
func (s UDSOType) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf("\"%v\"", s)), nil
}

// UnmarshalYAML implements the Unmarshaler interface of the yaml.v3 package for UDSOType.
func (s *UDSOType) UnmarshalYAML(unmarshal func(interface{}) error) error {
    var v string
    if err := unmarshal(&v); err != nil {
        return err
    }
    result, ok := mapUDSOTypeFromString[strings.ToLower(v)]  
    if !ok {
        return fmt.Errorf("%w: %s", ErrUnknownUDSOType, v)
    }
    *s = result
    return nil
}
