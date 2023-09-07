package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/VirusTotal/vt-go"
	"github.com/mpkondrashin/tmdetect/pkg/apex"
	"github.com/mpkondrashin/tmdetect/pkg/vtotal"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const EnvPrefix = "TMDETECT"

const (
	ConfigFileName = "config"
	ConfigFileType = "yaml"
)

const (
	flagVTApiKey          = "vtotal.api_key"
	flagVTProxy           = "vtotal.proxy"
	flagVTDispatchers     = "vtotal.threads"
	flagACURL             = "acentral.url"
	flagACAPIKey          = "acentral.api_key"
	flagACProxy           = "acentral.proxy"
	flagACAppID           = "acentral.app_id"
	flagACIgnoreTLSErrors = "acentral.ignore_tls_errors"
	flagTimeout           = "timeout"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)

	fs.String(flagVTApiKey, "", "VirusTotal API key")
	fs.String(flagVTProxy, "", "Proxy to connect to Virus Total (https://www.virustotal.com/api/)")
	fs.Int(flagVTDispatchers, 5, "Simultaneous connections to Virus Total")
	fs.String(flagACURL, "", "Apex Central URL")
	fs.String(flagACAPIKey, "", "Apex Central API key")
	fs.String(flagACAppID, "", "Apex Central Application ID")
	fs.String(flagACProxy, "", "Proxy to connect to Apex Central")
	fs.Bool(flagACIgnoreTLSErrors, false, "Ignore TLS errors")
	fs.Duration(flagTimeout, 0, "Stop program after this timeout")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := viper.BindPFlags(fs); err != nil {
		log.Fatal(err)
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()
	fmt.Println(os.Getenv("TMDETECT_ACENTRAL_URL"))

	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType(ConfigFileType)
	path, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(path)
		viper.AddConfigPath(dir)
	}
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		_, ok := err.(viper.ConfigFileNotFoundError)
		if !ok {
			log.Fatal(err)
		}
	}
}

func GetNonEmpty(flag string) string {
	result := viper.GetString(flag)
	if result == "" {
		log.Fatalf("parameter is missing: %s", flag)
	}
	return result
}

func GetApexCentral() *apex.Central {
	acURL := GetNonEmpty(flagACURL)
	acAppID := GetNonEmpty(flagACAppID)
	acAPIKey := GetNonEmpty(flagACAPIKey)
	central := apex.NewCentral(acURL, acAppID, acAPIKey)
	central.SetIgnoreTLSError(viper.GetBool(flagACIgnoreTLSErrors))
	central.SetProxy(viper.GetString(flagACProxy))
	return central
}

func GetVTClient() *vt.Client {
	vtAPIKey := GetNonEmpty(flagVTApiKey)
	proxy := viper.GetString(flagVTProxy)
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.Fatalf("%s: %v", flagVTProxy, err)
		}
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		httpClient := http.Client{Transport: transport}
		withProxy := vt.WithHTTPClient(&httpClient)
		return vt.NewClient(vtAPIKey, withProxy)
	}
	return vt.NewClient(vtAPIKey)
}

func main() {
	log.Print("ACentral started")
	duration := viper.GetDuration(flagTimeout)
	stopTime := time.Time{}
	if duration != 0 {
		stopTime = time.Now().Add(duration)
		log.Printf("Stop time %v (%v)", stopTime, duration)
	}
	Configure()
	central := GetApexCentral()
	client := GetVTClient()

	list := central.UDSOList(apex.UDSOTypeFile_sha1)
	data, err := list.Do(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got %d SHA1 UDSO from ApexCentral (%s)", len(data), viper.GetString(flagACURL))
	SortSO(data)

	log.Println("Get quota")
	response, err := vtotal.GetVTQuota(client)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Monthly quota: %d", response.APIRequestsMonthly.User.Allowed)
	log.Printf("Daily quota: %d", response.APIRequestsDaily.User.Allowed)
	log.Printf("Hourly quota: %d", response.APIRequestsHourly.User.Allowed)
	estimatedTime, estimatedDuration := response.EstimateFinishTimePublic(len(data))
	log.Printf("Estimated script run time: %v", estimatedDuration.Round(time.Second))
	log.Printf("Estimated complete time: %v", estimatedTime.Local().Format(time.DateTime))
	if !stopTime.IsZero() && estimatedTime.After(stopTime) {
		log.Println("TMDetect will not complete processing all indicators and stop by timeout")
	}
	dispatchers := viper.GetInt(flagVTDispatchers)
	quota := response.Quota()
	if !quota.IsPremium() {
		log.Printf("Virus Total Public API. \"%s\" parameter is reset to 1", flagVTDispatchers)
		dispatchers = 1
	}
	//	for i, each := range data {
	//		log.Printf("%d. %v: %s - %v", i, each.Type, each.Content, each.ExpirationUtcDate)
	//	}

	inbox := make(chan apex.UDSOListItem)
	limited := make(chan apex.UDSOListItem)
	detected := make(chan apex.UDSOListItem)
	undetected := make(chan apex.UDSOListItem)

	var wg sync.WaitGroup
	wg.Add(1)
	go UpdateUDSODispatch(undetected, central, &wg)
	wg.Add(1)
	go DeleteUDSODispatch(detected, central, &wg)

	vtDispatch := NewVTDispatch(client, quota, limited, detected, undetected)
	log.Printf("Number of simultanious connections to Virus Total: %d", dispatchers)
	go vtDispatch.Run(dispatchers)

	go QuotaDispatch(quota, inbox, limited)

	count := 0
	for n, so := range data {
		if !stopTime.IsZero() && time.Now().After(stopTime) {
			log.Println("Timeout")
			log.Printf("Missed checking %d indicators checked less then %v time ago", len(data)-n, time.Now().Sub(LastVTCheck(so.Notes)))
			break
		}
		inbox <- so
		count++
	}
	close(inbox)
	wg.Wait()
	log.Printf("Processed total %d hashes", count)
	log.Println("Done")
}

func QuotaDispatch(q *vtotal.VTQuota, in, out chan apex.UDSOListItem) {
	log.Println("Quota Dispatch")
	for so := range in {
		now := time.Now().UTC()
		t := q.EstimateCompleteTime(now, 1)
		sleep := t.Sub(now)
		if sleep != 0 {
			log.Printf("Sleep %v until %v", sleep, t)
			time.Sleep(sleep)
		}
		out <- so
	}
	close(out)
}

func UpdateUDSODispatch(in chan apex.UDSOListItem, central *apex.Central, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("UpdateUDSODispatch")
	count := 0
	for so := range in {
		log.Printf("Update %s", so.Content)
		so.Notes = SetTimeStamp(so.Notes, time.Now())
		add := central.UDSOAddParam(&so)
		err := add.Do(context.TODO())
		if err != nil {
			log.Println(err)
		}
		count++
	}
	log.Printf("Updated %d hashes", count)
}

func DeleteUDSODispatch(in chan apex.UDSOListItem, central *apex.Central, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("DeleteUDSODispatch")
	count := 0
	for so := range in {
		log.Printf("Delete %s", so.Content)
		add := central.UDSODelete().SetType(apex.UDSOTypeFile_sha1).SetContent(so.Content)
		_, err := add.Do(context.TODO())
		if err != nil {
			log.Println(err)
		}
		count++
	}
	log.Printf("Deleted %d hashes", count)
}
