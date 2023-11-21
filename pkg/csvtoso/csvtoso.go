package csvtoso

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mpkondrashin/tmdetect/pkg/apex"
)

/*
parse CSV file
detect fields position
detect fields type

*/

func LoadCSV(reader io.Reader, comma rune) ([][]string, error) {
	r := csv.NewReader(reader)
	r.Comma = comma
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	return records, nil
}

func countRecords(records [][]string) (count int) {
	for _, row := range records {
		count += len(row)
	}
	return
}

func LoadCSVFile(fileName string) ([][]string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var longest [][]string
	var longestLength int
	commas := []rune{',', ';', ' ', '\t'}
	for _, comma := range commas {
		var records [][]string
		records, err = LoadCSV(f, comma)
		if err != nil {
			continue
		}
		l := countRecords(records)
		if l > longestLength {
			longestLength = l
			longest = records
		}
		f.Seek(0, io.SeekStart)
	}
	return longest, err
}

const stopWord = "filename"

var ErrNoIoCFound = errors.New("no IoCs found")

func ListIoCs(fileName string) ([]string, error) {
	records, err := LoadCSVFile(fileName)
	if err != nil {
		return nil, err
	}
	c := HeurIoCColumn(records)
	if c == -1 {
		return nil, fmt.Errorf("%s: %w", fileName, ErrNoIoCFound)
	}
	var result []string
	for _, row := range records {
		if SkipLine(row) {
			continue
		}
		ioc := row[c]
		fixed, _, err := DetectType(ioc)
		if err != nil {
			continue
		}
		result = append(result, fixed)
	}
	return result, nil
}

func IterateSO(fileName string, callback func(content string, typ apex.ObjectType) error) error {
	records, err := LoadCSVFile(fileName)
	if err != nil {
		return err
	}
	c := HeurIoCColumn(records)
	if c == -1 {
		return fmt.Errorf("%s: %w", fileName, ErrNoIoCFound)
	}
	for _, row := range records {
		if SkipLine(row) {
			continue
		}
		ioc := row[c]
		fixed, typ, err := DetectType(ioc)
		if err != nil {
			continue
		}
		if err := callback(fixed, typ); err != nil {
			return err
		}
	}
	return nil
}

func SkipLine(row []string) bool {
	for _, col := range row {
		if col == stopWord {
			return true
		}
	}
	return false
}

/*
	func IoCColumn(row []string) int {
		for i, s := range row {
			if s == stopWord {
				return -1
			}
			_, err := DetectType(s)
			//log.Println("For ", s, " detected ", t, err)
			if err == nil {
				return i
			}
		}
		return -1
	}
*/
func HeurIoCColumn(records [][]string) int {
	m := make(map[int]int)
	for _, row := range records {
		for c, s := range row {
			_, _, err := DetectType(s)
			if err != nil {
				continue
			}
			m[c]++
		}
	}
	result := 0
	highest := 0
	for i, n := range m {
		if n > highest {
			highest = n
			result = i
		}
	}
	return result
}

/*
func IterateCSVSO(csv io.Reader, callback func(*apex.SO) error) error {
	return iterateCSV(csv, func(s string) error {

		return nil
	})
}

func iterateCSV(csv io.Reader, callback func(string) error) error {
	scanner := bufio.NewScanner(csv)
	for scanner.Scan() {
		line := scanner.Text()
		commaSeparated := strings.Split(line, ",")
		for _, c := range commaSeparated {
			semicolonSeparated := strings.Split(c, ";")
			for _, s := range semicolonSeparated {
				if err := callback(s); err != nil {
					return err
				}
			}
		}
	}
	return scanner.Err()
}
*/
