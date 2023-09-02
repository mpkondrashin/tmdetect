package iocscsv

import (
	"encoding/csv"
	"errors"
	"io"
	"log"
	"os"
	"strings"
)

var (
	ErrUnknownType     = errors.New("unknown type")
	ErrUnsupportedType = errors.New("unsupported type")
)

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

func UsageExample() {
	tip, err := CSVRead(os.Args[1], nil)
	if err != nil {
		log.Fatal(err)
	}
	_ = tip
}
