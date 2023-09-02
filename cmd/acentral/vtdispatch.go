package main

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/VirusTotal/vt-go"
	"github.com/mpkondrashin/tmdetect/pkg/apex"
	"github.com/mpkondrashin/tmdetect/pkg/vtotal"
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
	quota      *vtotal.VTQuota
	client     *vt.Client
	in         chan apex.UDSOListItem
	detected   chan apex.UDSOListItem
	undetected chan apex.UDSOListItem
}

func NewVTDispatch(client *vt.Client, quota *vtotal.VTQuota, in, detected, undetected chan apex.UDSOListItem) *VTDispatch {
	return &VTDispatch{
		client:     client,
		quota:      quota,
		in:         in,
		detected:   detected,
		undetected: undetected,
	}
}

func (d *VTDispatch) Run(dispatchers int) {
	//	log.Printf("Run(%d)", dispatchers)
	var wg sync.WaitGroup
	for i := 0; i < dispatchers; i++ {
		//		log.Printf("Run dispatcher %d", i+1)
		wg.Add(1)
		go d.Routine(&wg)
	}
	wg.Wait()
	close(d.detected)
	close(d.undetected)
}

func (d *VTDispatch) Routine(wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("Virus Total Dispatch")
	for so := range d.in {
		//log.Printf("Routine: Got %s", so.Content)
		so.Notes = SetTimeStamp(so.Notes, time.Now())
		if d.IsDetected(so.Content) {
			log.Printf("Detected: %s", so.Content)
			d.detected <- so
		} else {
			log.Printf("Not detected: %s", so.Content)
			d.undetected <- so
		}
	}
}

func (d *VTDispatch) IsDetected(hash string) bool {
	//log.Printf("Malicious(%s)", hash)
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
				log.Println(err)
				log.Printf("Sleep %v: %v", sleepDuration, err)
				time.Sleep(sleepDuration)
				sleepDuration *= 2
				continue
			}
			//log.Println(err)
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
