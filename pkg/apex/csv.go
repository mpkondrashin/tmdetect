package apex

import (
	"fmt"
	"time"
)

const CSVHeading = "Version:V1,,,,,\nObject,Type,Scan Action,Scan Prefilter,Notes,ExpirationDate"

//go:generate enum -package apex -type ObjectType -names IP,Domain,URL,SHA1
//go:generate enum -package apex -type ScanAction -names Block,Log
type SO struct {
	Object        string
	Type          ObjectType
	Action        ScanAction
	ScanPrefilter string
	Notes         string
	ExirationDate time.Time
}

func (s *SO) String() string {
	return fmt.Sprintf("%s,%v,%v,%s,%s,%s", s.Object, s.Type, s.Action, s.ScanPrefilter, s.Notes, s.ExirationDate.Format("2006/01/02"))
}
