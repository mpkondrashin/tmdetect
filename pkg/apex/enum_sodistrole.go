// Code generated by enum (github.com/mpkondrashin/enum) using following command:
// enum -package apex -type SoDistRole -names none,hub,edge
// DO NOT EDIT!

package apex

import (
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "strings"
)

type SoDistRole int

const (
    SoDistRoleNone SoDistRole = iota
    SoDistRoleHub  SoDistRole = iota
    SoDistRoleEdge SoDistRole = iota
)


// String - return string representation for SoDistRole value
func (v SoDistRole)String() string {
    s, ok := map[SoDistRole]string {
         SoDistRoleNone: "none",
         SoDistRoleHub:  "hub",
         SoDistRoleEdge: "edge",
    }[v]
    if ok {
        return s
    }
    return "SoDistRole(" + strconv.FormatInt(int64(v), 10) + ")"
}

// ErrUnknownSoDistRole - will be returned wrapped when parsing string
// containing unrecognized value.
var ErrUnknownSoDistRole = errors.New("unknown SoDistRole")


var mapSoDistRoleFromString = map[string]SoDistRole{
    "none":    SoDistRoleNone,
    "hub":    SoDistRoleHub,
    "edge":    SoDistRoleEdge,
}

// UnmarshalJSON implements the Unmarshaler interface of the json package for SoDistRole.
func (s *SoDistRole) UnmarshalJSON(data []byte) error {
    var v string
    if err := json.Unmarshal(data, &v); err != nil {
        return err
    }
    result, ok := mapSoDistRoleFromString[strings.ToLower(v)]
    if !ok {
        return fmt.Errorf("%w: %s", ErrUnknownSoDistRole, v)
    }
    *s = result
    return nil
}

// MarshalJSON implements the Marshaler interface of the json package for SoDistRole.
func (s SoDistRole) MarshalJSON() ([]byte, error) {
    return []byte(fmt.Sprintf("\"%v\"", s)), nil
}

// UnmarshalYAML implements the Unmarshaler interface of the yaml.v3 package for SoDistRole.
func (s *SoDistRole) UnmarshalYAML(unmarshal func(interface{}) error) error {
    var v string
    if err := unmarshal(&v); err != nil {
        return err
    }
    result, ok := mapSoDistRoleFromString[strings.ToLower(v)]  
    if !ok {
        return fmt.Errorf("%w: %s", ErrUnknownSoDistRole, v)
    }
    *s = result
    return nil
}
