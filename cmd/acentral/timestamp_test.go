package main

import (
	"strconv"
	"testing"
	"time"

	"github.com/mpkondrashin/tmdetect/pkg/apex"
)

func TestLastVTCheck(t *testing.T) {
	testCases := []struct {
		notes    string
		expected string
	}{
		{"ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>CBA", "2020-02-03T11:01:04Z"},
		{"ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>DEF<TMDETECT_DATE>2020-02-04T11:01:04Z</TMDETECT_DATE>", "2020-02-04T11:01:04Z"},
		{"ABC<TMDETECT_DATE>2020-02-04T11:01:04Z</TMDETECT_DATE>DEF<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>", "2020-02-04T11:01:04Z"},
		{"ABC<TMDETECT_DATE>2020</TMDETECT_DATE>DEF", "0001-01-01T00:00:00Z"},
		{"ABC", "0001-01-01T00:00:00Z"},
		{"", "0001-01-01T00:00:00Z"},
	}
	for n, tCase := range testCases {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			actualTime := LastVTCheck(tCase.notes)
			actual := actualTime.Format(TimeStampFormat)
			if tCase.expected != actual {
				t.Errorf("Expected %v, but got %v", tCase.expected, actual)
			}
		})
	}
}

func TestSetTimeStamp(t *testing.T) {
	now := "2020-02-03T11:01:04Z"
	stamp, err := time.Parse(TimeStampFormat, now)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		notes    string
		expected string
	}{
		{"", "<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>"},
		{"ABC", "ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>"},
		{"ABC<TMDETECT_DATE>2020-02-04T11:01:04Z</TMDETECT_DATE>", "ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>"},
		{"ABC<TMDETECT_DATE>2020-02-04T11:01:04Z</TMDETECT_DATE>DEF", "ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>DEF"},
		{"ABC<TMDETECT_DATE>2020-02-04T11:01:04Z</TMDETECT_DATE>DEF<TMDETECT_DATE>2020-02-05T11:01:04Z</TMDETECT_DATE>GHI", "ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>DEFGHI"},
	}
	for n, tCase := range testCases {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			actual := SetTimeStamp(tCase.notes, stamp)
			if tCase.expected != actual {
				t.Errorf("Expected %v, but got %v", tCase.expected, actual)
			}
		})
	}
}

func TestSortSO(t *testing.T) {
	a := apex.UDSOListItem{
		Notes: "ABC<TMDETECT_DATE>2020-02-03T11:01:04Z</TMDETECT_DATE>DEF",
	}
	b := apex.UDSOListItem{
		Notes: "ABC<TMDETECT_DATE>2020-02-02T11:01:04Z</TMDETECT_DATE>DEF",
	}
	list := apex.UDSOListData{
		a, b,
	}
	SortSO(list)
	if list[0] != b {
		t.Errorf("first element is not %v", b)
	}
	if list[1] != a {
		t.Errorf("second element is not %v", a)
	}
}
