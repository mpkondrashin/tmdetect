package csvtoso

import (
	"testing"

	"github.com/asaskevich/govalidator"
	"github.com/mpkondrashin/tmdetect/pkg/apex"
)

func TestIterateSO(t *testing.T) {
	records, err := LoadCSVFile("corpus/0004.csv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range records {
		t.Log(line[0])
	}
}

func TestIsDomain(t *testing.T) {
	testCases := []struct {
		domain   string
		expected bool
	}{
		{"wef", false},
		{"1", false},
		{"www[.com", false},
		{"www.com", true},
		{"www[.]com", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.domain, func(t *testing.T) {
			_, actual := IsDNSName(testCase.domain)
			if actual != testCase.expected {
				t.Errorf("For %s got %v and not %v", testCase.domain, actual, testCase.expected)
			}
		})
	}
}

func TestIsURL(t *testing.T) {
	testCases := []struct {
		domain   string
		fixed    string
		expected bool
	}{
		{"wef", "wef", false},
		{"hxxps://storage[.]googleapis[.]com/yhrb4u5u8fo5[.]appspot[.]com/w/C3ptSnKGvbUfdXf[.]html?a=910675785738954864", "https://storage.googleapis.com/yhrb4u5u8fo5.appspot.com/w/C3ptSnKGvbUfdXf.html?a=910675785738954864", true},
		{"hxxps://45[.]117[.]103[.]135/Compare/v2[.]66/G6EBS8VJR0", "https://45.117.103.135/Compare/v2.66/G6EBS8VJR0", true},
		{"www.com", "www.com", true},
		{"www[.]com", "www.com", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.domain, func(t *testing.T) {
			fixed, actual := IsURL(testCase.domain)
			if actual != testCase.expected {
				t.Errorf("For %s got %v and not %v", testCase.domain, actual, testCase.expected)
			}
			if fixed != testCase.fixed {
				t.Errorf("For %s got %v and not %v", testCase.domain, fixed, testCase.fixed)
			}
		})
	}
}
func TestHeurIoCColumn(t *testing.T) {
	records := [][]string{
		{"1", "2", "1.2.3.4"},
		{"1", "2", "5.6.7.8"},
		{"1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "5.6.7.8"},
		{"1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "5.6.7.8"},
		{"1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "5.6.7.8"},
		{"1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "5.6.7.8"},
		{"www.ru", "2", "3"},
		{"www.ru", "2", "3"},
		{"www.ru", "2", "3"},
	}
	expected := 2
	actual := HeurIoCColumn(records)
	if actual != expected {
		t.Errorf("Expected %d, but got %d", expected, actual)
	}
}

func TestDetect(t *testing.T) {
	sha1 := "1b9afad227b98c17fc6b1a295c07399efd3641f3"
	sha256 := "7e6835e11f4d3cd674c8d2784ce0dd34d2dce6344bbd5a9dbddc411140160405"
	testCases := []struct {
		content  string
		fixed    string
		expected apex.ObjectType
	}{
		{"http//abc.com", "", -1},
		{"hxxp//185[.]225[.]73[.]196/ssh/new/x86v", "", -1},
		{"185[.]225[.]73[.]196/ssh/new/x86v", "https://185.225.73.196/ssh/new/x86v", apex.ObjectTypeUrl},
		{"asdf.esdf[.]com", "asdf.esdf.com", apex.ObjectTypeDomain},
		{"1[.]2.3.4", "1.2.3.4", apex.ObjectTypeIp},
		{"hxxps://1.2.3.4:2132/asdfasdf.asd?a=x&e=q", "https://1.2.3.4:2132/asdfasdf.asd?a=x&e=q", apex.ObjectTypeUrl},
		{sha1, sha1, apex.ObjectTypeSha1},
		{sha256, sha256, apex.ObjectTypeSha256},
	}
	for _, testCase := range testCases {
		t.Run(testCase.content, func(t *testing.T) {
			fixed, actual, err := DetectType(testCase.content)
			if err != nil {
				if testCase.expected != -1 {
					t.Error(err)
				}
				return
			}
			if actual != testCase.expected {
				t.Errorf("For %s got %v and not %v", testCase.content, actual, testCase.expected)
			}
			if fixed != testCase.fixed {
				t.Errorf("For %s got %v and not %v", testCase.content, fixed, testCase.fixed)
			}
		})
	}
}

func TestMain1(t *testing.T) {
	t.Log(govalidator.IsURL("http//abc.com"))
}

/*
func TestLoad(t *testing.T) {
	records, err := ListIoCs("Mops_Amber_IOCs_18082022.csv")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Create("out.txt")
	for _, l := range records {
		fmt.Fprintln(f, l)
	}
	f.Close()

}
*/
