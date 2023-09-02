package main

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mpkondrashin/tmdetect/pkg/apex"
)

var (
	StampPrefix        = "<TMDETECT_DATE>"
	StampPostfix       = "</TMDETECT_DATE>"
	LastCheckTime      = StampPrefix + "(.+?)" + StampPostfix
	LastCheckTimeRegex = regexp.MustCompile(LastCheckTime)
)

const TimeStampFormat = time.RFC3339

func LastVTCheck(notes string) time.Time {
	s := LastCheckTimeRegex.FindAllStringSubmatch(notes, -1)
	if s == nil {
		return time.Time{}
	}
	latest := ""
	for _, each := range s {
		if each[1] > latest {
			latest = each[1]
		}
	}
	t, err := time.Parse(TimeStampFormat, latest)
	if err != nil {
		//log.Println(err)
		return time.Time{}
	}
	return t
}

func SortSO(list apex.UDSOListData) {
	sort.Slice(list, func(i, j int) bool {
		a := LastVTCheck(list[i].Notes)
		b := LastVTCheck(list[j].Notes)
		return a.Before(b)
	})
}

func SetTimeStamp(notes string, stamp time.Time) string {
	split := LastCheckTimeRegex.Split(notes, -1)
	newStamp := StampPrefix + stamp.Format(TimeStampFormat) + StampPostfix
	return split[0] + newStamp + strings.Join(split[1:], "")
}
