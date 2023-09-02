package vtotal

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/VirusTotal/vt-go"
)

const (
	// VirusTotal API errors -  https://developers.virustotal.com/reference/errors
	BadRequestError              = "BadRequestError"
	InvalidArgumentError         = "InvalidArgumentError"
	NotAvailableYet              = "NotAvailableYet"
	UnselectiveContentQueryError = "UnselectiveContentQueryError"
	UnsupportedContentQueryError = "UnsupportedContentQueryError"
	AuthenticationRequiredError  = "AuthenticationRequiredError"
	UserNotActiveError           = "UserNotActiveError"
	WrongCredentialsError        = "WrongCredentialsError"
	ForbiddenError               = "ForbiddenError"
	NotFoundError                = "NotFoundError"
	AlreadyExistsError           = "AlreadyExistsError"
	FailedDependencyError        = "FailedDependencyError"
	QuotaExceededError           = "QuotaExceededError"
	TooManyRequestsError         = "TooManyRequestsError"
	TransientError               = "TransientError"
	DeadlineExceededError        = "DeadlineExceededError"
)

type VTDispatch struct {
	quota  *VTQuota
	client *vt.Client
	in     chan string
	out    chan string
}

func NewVTDispatch(client *vt.Client, quota *VTQuota, in chan string, out chan string) *VTDispatch {
	return &VTDispatch{
		client: client,
		quota:  quota,
		in:     in,
		out:    out,
	}
}

func (d *VTDispatch) Run(dispatchers int) {
	var wg sync.WaitGroup
	for i := 0; i < dispatchers; i++ {
		wg.Add(1)
		go d.Routine(&wg)
	}
	wg.Wait()
	close(d.out)
}

func (d *VTDispatch) Routine(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("VT Dispatch")
	for hash := range d.in {
		if d.Malicious(hash) {
			log.Printf("Malicious: %s", hash)
			continue
		}
		log.Printf("Unmalicious: %s", hash)
		d.out <- hash
	}
}

func (d *VTDispatch) Malicious(hash string) bool {
	sleepDuration := 1 * time.Second
	tries := 16
	for i := 1; i <= tries; i++ {
		log.Printf("Check %d hash %s ", i, hash)
		file, err := d.client.GetObject(vt.URL("files/%s", hash))
		// no error
		// VT err - should retry
		// VT err - should skip
		// VT err - fatal
		// transport error - ?
		if err != nil {
			if d.Retry(err) {
				log.Printf("Sleep %v: %v", sleepDuration, err)
				time.Sleep(sleepDuration)
				sleepDuration *= 2
				continue
			}
			log.Println(err)
			return false
		}
		jsonPath := "last_analysis_results.TrendMicro.category"
		category, err := file.GetString(jsonPath)
		if err != nil {
			log.Printf("Get \"%s\": %v", jsonPath, err)
			return false
		}
		return category == "malicious"
	}
	return false
}

//result, err := file.Get("last_analysis_results.TrendMicro.result") //method
//	fmt.Printf("File %s, %s, %s\n", file.ID(), category, sres)
/*
type ErrorLevel int

const (
	NoError ErrorLevel = iota
	TemporaryError
	PermanentError
	FatalError
)*/

func (d *VTDispatch) Retry(err error) bool {
	var vtErr vt.Error
	if errors.As(err, &vtErr) {
		switch vtErr.Code {
		case AuthenticationRequiredError,
			WrongCredentialsError:
			log.Fatalf("%s: %s", vtErr.Code, vtErr.Message)
		case BadRequestError,
			InvalidArgumentError,
			UnselectiveContentQueryError,
			UnsupportedContentQueryError,
			UserNotActiveError,

			ForbiddenError,
			NotFoundError,
			AlreadyExistsError,
			FailedDependencyError:
			return false
		case NotAvailableYet,
			QuotaExceededError,
			TooManyRequestsError,
			TransientError,
			DeadlineExceededError:
			return true
		default:
			log.Printf("Unexpected VirusTotal API error: %s (%s)", vtErr.Code, vtErr.Message)
			return false
		}
	}
	log.Printf("Transport error: %s (%T)", err, err)
	return false
}
