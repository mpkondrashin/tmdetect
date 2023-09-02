package apex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type Permission int

const (
	ReadOnly    Permission = 1
	FullControl Permission = 255
)

var ErrUnknownPermission = errors.New("unknown Permission")

// String - return string representation for Permission value
func (v Permission) String() string {
	s, ok := map[Permission]string{
		ReadOnly:    "ReadOnly",
		FullControl: "FullControl",
	}[v]
	if ok {
		return s
	}
	return "Permission(" + strconv.FormatInt(int64(v), 10) + ")"
}

// UnmarshalJSON implements the Unmarshaler interface of the json package for Permission.
func (s *Permission) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	p, err := strconv.Atoi(v)
	if err != nil {
		return err
	}
	*s = Permission(p)
	return nil
}

// MarshalJSON implements the Marshaler interface of the json package for Permission.
func (s Permission) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%v\"", s)), nil
}
