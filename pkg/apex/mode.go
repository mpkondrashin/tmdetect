package apex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type Mode int

const (
	ApexCentralSaaS       Mode = 0
	ApexCentralOnPremises Mode = 1
)

// String - return string representation for Mode value
func (v Mode) String() string {
	s, ok := map[Mode]string{
		ApexCentralSaaS:       "ApexCentralSaaS",
		ApexCentralOnPremises: "ApexCentralOnPremises",
	}[v]
	if ok {
		return s
	}
	return "Mode(" + strconv.FormatInt(int64(v), 10) + ")"
}

// ErrUnknownMode - will be returned wrapped when parsing string
// containing unrecognized value.
var ErrUnknownMode = errors.New("unknown Mode")

// UnmarshalJSON implements the Unmarshaler interface of the json package for Mode.
func (s *Mode) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("Unmarshal Mode: %w", err)
	}
	m, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnknownMode, err)
	}
	mode := Mode(m)
	if mode != ApexCentralSaaS && mode != ApexCentralOnPremises {
		return fmt.Errorf("%s: %w", v, ErrUnknownMode)
	}
	*s = mode
	return nil
}

// MarshalJSON implements the Marshaler interface of the json package for Mode.
func (s Mode) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Itoa(int(s))), nil
}
