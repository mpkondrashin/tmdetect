package iocscsv

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnknownType     = errors.New("unknown type")
	ErrUnsupportedType = errors.New("unsupported type")
)

//go:generate enum -package iocscsv -type ThreatType -names md5,sha256,url,email-src,ip-dst,btc,hostname,domain,filename,sha1
//go:generate enum -package iocscsv -type Severity -names Low,Medium,High
//go:generate enum -package iocscsv -type Vector -names "Network activity,Financial fraud,Payload delivery"

// uuid,category,type,value,event_threat_level_id,date

type IoC struct {
	UUID     string
	Vector   Vector
	Type     ThreatType
	Content  string
	Severity Severity
	Time     time.Time
}

// 0 ce2d3596-c7b5-485d-a329-20e22ac93141,
// 1 Network activity,
//2 url,
// 3 hxxp://62[.]109[.]4[.]67/tojavascript_temporary[.]php,
//  4/ Medium,
//5  1660844337

func NewIoC(line []string) (*IoC, error) {
	uuid, vector, kind, content, severity, tim := line[0], line[1], line[2], line[3], line[4], line[5]
	ioc := IoC{
		UUID:    uuid,
		Content: content,
	}
	if err := ioc.Vector.UnmarshalJSON([]byte("\"" + vector + "\"")); err != nil {
		return nil, err
	}
	if err := ioc.Type.UnmarshalJSON([]byte("\"" + kind + "\"")); err != nil {
		return nil, err
	}
	if err := ioc.Severity.UnmarshalJSON([]byte("\"" + severity + "\"")); err != nil {
		return nil, err
	}
	t, err := strconv.ParseInt(tim, 10, 64)
	if err != nil {
		return nil, err
	}
	ioc.Time = time.Unix(t, 0)
	if ioc.Type == ThreatTypeUrl || ioc.Type == ThreatTypeDomain || ioc.Type == ThreatTypeIp_dst || ioc.Type == ThreatTypeEmail_src {
		ioc.Content = unmaskURL(ioc.Content)
	}
	return &ioc, nil
}

/*
	func isHash(s string) (bool, error) {
		switch s {
		case "md5", "sha256", "url", "email-src", "ip-dst", "btc", "hostname", "domain", "filename":
			return false, fmt.Errorf("%s: %w", s, ErrUnsupportedType)
		case "sha1":
			return true, nil
		default:
			return false, ErrUnknownType
		}
	}
*/

func CSVReadFile(input io.Reader, filter func(string) bool) ([]string, error) { //map[string]int, error) {
	reader := csv.NewReader(input)
	//r.Comma = ';'
	//r.Comment = '#'
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	//stat := make(map[string]int)
	var output []string
	for _, line := range records[1:] {
		if len(line) < 4 {
			log.Fatalf("Can not parse line: %s", strings.Join(line, ","))
		}
		kindStr := line[2]
		//		stat[kindStr] += 1
		process := true
		if filter != nil {
			process = filter(kindStr)
		}
		/*if err != nil {
			if errors.Is(err, ErrUnsupportedType) {
				continue
			}
		}*/
		if !process {
			continue
		}
		value := line[3]
		if kindStr == "url" {
			value = unmaskURL(value)
		}
		output = append(output, value)
	}
	return output, nil
}

func CSVRead(fileName string, filter func(string) bool) ([]string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	return CSVReadFile(file, filter)
}

func CSVIterate(input io.Reader, callback func(*IoC) error) error {
	reader := csv.NewReader(input)
	//r.Comma = ';'
	//r.Comment = '#'
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	//stat := make(map[string]int)
	for _, line := range records[1:] {
		if len(line) < 4 {
			return fmt.Errorf("Can not parse line: %s", strings.Join(line, ","))
		}
		ioc, err := NewIoC(line)
		if err != nil {
			return err
		}
		if err := callback(ioc); err != nil {
			return err
		}
	}
	return nil
}

func UsageExample() {
	tip, err := CSVRead(os.Args[1], nil)
	if err != nil {
		log.Fatal(err)
	}
	_ = tip
}

func unmaskURL(url string) string {
	//      hxxps://storage[.]googleapis[.]com/f50awc2m6bnj[.]appspot[.]com/w/dYueD9RXGH2qCQQ[.]html?b=394909745746782860
	if strings.HasPrefix(url, "hxxp") {
		url = "http" + url[4:]
	}
	return strings.ReplaceAll(url, "[.]", ".")
}
