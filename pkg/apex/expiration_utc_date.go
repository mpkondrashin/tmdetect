package apex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ExpirationUTCDate time.Time

const format = "2006-01-02T15:04:05"

// String - return string representation for SoDistRole value
func (t ExpirationUTCDate) String() string {
	if time.Time(t).IsZero() {
		return "null"
	}
	return time.Time(t).Format(format)
}

// UnmarshalJSON implements the Unmarshaler interface of the json package for ExpirationUTCDate.
func (t *ExpirationUTCDate) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if string(data) == "null" {
		*t = ExpirationUTCDate(time.Time{})
		return nil
	}
	result, err := time.Parse(format, strings.Trim(string(data), "\""))
	if err != nil {
		return err
	}
	*t = ExpirationUTCDate(result)
	return nil
}

// MarshalJSON implements the Marshaler interface of the json package for ExpirationUTCDate.
func (t ExpirationUTCDate) MarshalJSON() ([]byte, error) {
	if time.Time(t).IsZero() {
		return []byte("null"), nil
	}
	return []byte(fmt.Sprintf("\"%v\"", t)), nil
}
