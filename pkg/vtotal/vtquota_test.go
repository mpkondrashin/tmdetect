package vtotal

import (
	"fmt"
	"os"
	"testing"
	"time"
)

type TestCase struct {
	Monthly  int
	Daily    int
	Hourly   int
	Requests int
	Expected time.Time
}

func (t TestCase) String() string {
	return fmt.Sprintf("M%d_D%d_H%d_R%d", t.Monthly, t.Daily, t.Hourly, t.Requests)
}
func TestEstimatedFinishTimePublic(t *testing.T) {
	now := time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)

	f, _ := os.Create("a.csv")
	defer f.Close()
	start := now.Unix()
	for i := 0; i < 1100; i++ {
		quota := &VTQuotaResponse{}
		quota.APIRequestsMonthly.User.Allowed = 100
		quota.APIRequestsDaily.User.Allowed = 30
		quota.APIRequestsHourly.User.Allowed = 10
		a := quota.EstimateFinishTimePublicAt(now, i+1)
		fmt.Fprintf(f, "\"%d\";\"%d\";\"%v\"\n", i+1, a.Unix()-start, a)
	}

	quota := &VTQuotaResponse{}
	quota.APIRequestsMonthly.User.Allowed = 1000
	quota.APIRequestsDaily.User.Allowed = 100
	quota.APIRequestsHourly.User.Allowed = 10
	n1 := time.Date(2023, 3, 5, 23, 59, 59, 0, time.UTC)
	actualTime := quota.EstimateFinishTimePublicAt(n1, 8)
	e1 := time.Date(2023, 3, 5, 23, 59, 01, 0, time.UTC)
	if actualTime != e1 {
		t.Fatalf("%v != expected %v", actualTime, e1)
	}

	testCases := []TestCase{
		{1000, 100, 10, 3, time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)},
		{1000, 100, 10, 4, time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)},
		{1000, 100, 10, 5, time.Date(2023, 3, 5, 20, 16, 0, 0, time.UTC)},
		{1000, 100, 10, 9, time.Date(2023, 3, 5, 20, 17, 0, 0, time.UTC)},
		{1000, 100, 10, 10, time.Date(2023, 3, 5, 20, 17, 0, 0, time.UTC)},
		{1000, 100, 10, 11, time.Date(2023, 3, 5, 21, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 12, time.Date(2023, 3, 5, 21, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 13, time.Date(2023, 3, 5, 21, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 20, time.Date(2023, 3, 5, 21, 2, 0, 0, time.UTC)},
		{1000, 100, 10, 21, time.Date(2023, 3, 5, 22, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 22, time.Date(2023, 3, 5, 22, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 23, time.Date(2023, 3, 5, 22, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 24, time.Date(2023, 3, 5, 22, 0, 0, 0, time.UTC)},
		{1000, 100, 10, 25, time.Date(2023, 3, 5, 22, 1, 0, 0, time.UTC)},
		{1000, 100, 10, 30, time.Date(2023, 3, 5, 22, 2, 0, 0, time.UTC)},
		//{1000, 100, 10, 30, time.Date(2023, 3, 5, 22, 2, 0, 0, time.UTC)},
	}
	for _, tCase := range testCases {
		t.Run(tCase.String(), func(t *testing.T) {
			quota := &VTQuotaResponse{}
			quota.APIRequestsMonthly.User.Allowed = tCase.Monthly
			quota.APIRequestsDaily.User.Allowed = tCase.Daily
			quota.APIRequestsHourly.User.Allowed = tCase.Hourly
			actualTime := quota.EstimateFinishTimePublicAt(now, tCase.Requests)
			if actualTime != tCase.Expected {
				t.Errorf("%v != expected %v", actualTime, tCase.Expected)
			}
		})
	}
}

func TestVTQuota(t *testing.T) {
	{
		now := time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)
		q := NewVTQuota(NewLimit(1, 3), NewLimit(1, 10), NewLimit(1, 100), NewLimit(1, 1000))
		s := q.SleepUntil(now)
		expected := now
		if s != now {
			t.Errorf("%v != expected %v", s, expected)
		}
	}
	{
		now := time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)
		q := NewVTQuota(NewLimit(2, 3), NewLimit(1, 10), NewLimit(1, 100), NewLimit(1, 1000))
		s := q.SleepUntil(now)
		expected := now
		if s != now {
			t.Errorf("%v != expected %v", s, expected)
		}
	}
	{
		now := time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)
		q := NewVTQuota(NewLimit(3, 3), NewLimit(1, 10), NewLimit(1, 100), NewLimit(1, 1000))
		s := q.SleepUntil(now)
		expected := time.Date(2023, 3, 5, 20, 16, 0, 0, time.UTC)
		if s != expected {
			t.Errorf("%v != expected %v", s, expected)
		}
	}
	{
		now := time.Date(2023, 3, 5, 20, 15, 23, 0, time.UTC)
		q := NewVTQuota(NewLimit(3, 3), NewLimit(10, 10), NewLimit(1, 100), NewLimit(1, 1000))
		s := q.SleepUntil(now)
		expected := time.Date(2023, 3, 5, 21, 0, 0, 0, time.UTC)
		if s != expected {
			t.Errorf("%v != expected %v", s, expected)
		}
	}
}
