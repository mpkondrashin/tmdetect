package vtotal

import (
	"encoding/json"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

type VTQuotaResponse struct {
	IntelligenceVtdiffCreationMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_vtdiff_creation_monthly"`
	MonitorUploadedFiles struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"monitor_uploaded_files"`
	MonitorUploadedBytes struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"monitor_uploaded_bytes"`
	MonitorStorageFiles struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"monitor_storage_files"`
	APIRequestsMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"api_requests_monthly"`
	CollectionsCreationMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"collections_creation_monthly"`
	IntelligenceDownloadsMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_downloads_monthly"`
	APIRequestsHourly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"api_requests_hourly"`
	IntelligenceHuntingRules struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_hunting_rules"`
	IntelligenceGraphsPrivate struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_graphs_private"`
	APIRequestsDaily struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"api_requests_daily"`
	MonitorStorageBytes struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"monitor_storage_bytes"`
	PrivateScansMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"private_scans_monthly"`
	IntelligenceRetrohuntJobsMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_retrohunt_jobs_monthly"`
	IntelligenceSearchesMonthly struct {
		User struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"user"`
	} `json:"intelligence_searches_monthly"`
}

func (q *VTQuotaResponse) EstimateFinishTimePublic(requests int) (time.Time, time.Duration) {
	now := time.Now().UTC()
	t := q.EstimateFinishTimePublicAt(now, requests)
	return t, t.Sub(now)
}

func (q *VTQuotaResponse) Quota() *VTQuota {
	quotaPerMinute := 4
	if q.APIRequestsHourly.User.Allowed == 0 {
		quotaPerMinute = 0
	}
	minuteLimit := NewLimit(0, quotaPerMinute)
	monthLimit := NewLimit(q.APIRequestsMonthly.User.Used, q.APIRequestsMonthly.User.Allowed)
	dayLimit := NewLimit(q.APIRequestsDaily.User.Used, q.APIRequestsDaily.User.Allowed)
	hourLimit := NewLimit(q.APIRequestsHourly.User.Used, q.APIRequestsHourly.User.Allowed)
	return NewVTQuota(minuteLimit, hourLimit, dayLimit, monthLimit)
}

func (q *VTQuotaResponse) EstimateFinishTimePublicAt(now time.Time, requests int) time.Time {
	quota := q.Quota()
	result := now
	for i := 0; i < requests; i++ {
		result = quota.SleepUntil(result)
	}
	return result
}

func beginningOfNextMonths(now time.Time, months int) time.Time {
	nextMonth := now.AddDate(0, months, 0)
	return time.Date(nextMonth.Year(), nextMonth.Month(), 1, 0, 0, 0, 0, now.Location())
}

func beginningOfNextDays(now time.Time, days int) time.Time {
	nextDay := now.AddDate(0, 0, days)
	return time.Date(nextDay.Year(), nextDay.Month(), nextDay.Day(), 0, 0, 0, 0, now.Location())
}

func beginningOfNextHours(now time.Time, hours int) time.Time {
	nextHour := now.Add(time.Duration(hours) * time.Hour)
	return time.Date(nextHour.Year(), nextHour.Month(), nextHour.Day(), nextHour.Hour(), 0, 0, 0, now.Location())
}

func beginningOfNextMinutes(now time.Time, minutes int) time.Time {
	nextMinute := now.Add(time.Duration(minutes) * time.Minute)
	return time.Date(nextMinute.Year(), nextMinute.Month(), nextMinute.Day(), nextMinute.Hour(), nextMinute.Minute(), 0, 0, now.Location())
}

type Limit struct {
	used  int
	quota int
}

func NewLimit(value, limit int) Limit {
	return Limit{value, limit}
}

func (l *Limit) Reset() {
	l.used = 1
}

func (l *Limit) Exhausted() bool {
	if l.quota == 0 {
		return false
	}
	l.used++
	if l.used > l.quota {
		l.used = 1
		return true
	}
	return false
}

const (
	PublicAPIMonthlyQuota = 1000000000
	PublicAPIDailyQuota   = 500
	PublicAPIHourlyQuota  = 240
)

type VTQuota struct {
	minute Limit
	hour   Limit
	day    Limit
	month  Limit
}

func NewVTQuota(minute Limit, hour Limit, day Limit, month Limit) *VTQuota {
	return &VTQuota{
		minute: minute,
		hour:   hour,
		day:    day,
		month:  month,
	}
}

func (q *VTQuota) IsPremium() bool {
	return q.hour.quota != PublicAPIHourlyQuota && q.day.quota != PublicAPIDailyQuota && q.month.quota != PublicAPIMonthlyQuota
}

func (q *VTQuota) SleepUntil(now time.Time) (result time.Time) {
	result = now
	mon := q.month.Exhausted()
	day := q.day.Exhausted()
	hour := q.hour.Exhausted()
	min := q.minute.Exhausted()
	//fmt.Println("min", min, q.minute, "hour", hour, q.hour, "day", day, q.day, "month", mon, q.month)
	if mon {
		result = beginningOfNextMonths(now, 1)
	} else if day {
		result = beginningOfNextDays(now, 1)
	} else if hour {
		result = beginningOfNextHours(now, 1)
	} else if min {
		result = beginningOfNextMinutes(now, 1)
	}
	if result.Minute() != now.Minute() {
		q.minute.Reset()
	}
	if result.Hour() != now.Hour() {
		q.hour.Reset()
	}
	if result.Day() != now.Day() {
		q.day.Reset()
	}
	if result.Month() != now.Month() {
		q.month.Reset()
	}
	return result
}

func (q *VTQuota) EstimateCompleteTime(now time.Time, requests int) time.Time {
	result := now
	for i := 0; i < requests; i++ {
		result = q.SleepUntil(result)
	}
	return result
}

func GetVTQuota(client *vt.Client) (*VTQuotaResponse, error) {
	quota, err := client.Get(vt.URL("users/%s/overall_quotas", client.APIKey))
	if err != nil {
		return nil, err
	}
	var response VTQuotaResponse
	//fmt.Println(string(quota.Data))
	if err := json.Unmarshal(quota.Data, &response); err != nil {
		return nil, err
	}
	return &response, err
}
