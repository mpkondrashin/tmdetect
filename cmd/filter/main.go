package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/mpkondrashin/tmdetect/pkg/apex"
	"github.com/mpkondrashin/tmdetect/pkg/iocscsv"
	"github.com/mpkondrashin/tmdetect/pkg/vtotal"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

/*
csv
|
V
prefilter
|
hash
|
V
[VT], [VT], [VT], [VT], [VT]
|
Result
|
V
Save/alert/log/...
*/
const (
	EnvPrefix = "TMDETECT"
)

const (
	ConfigFileName = "config"
	ConfigFileType = "yaml"
)

const (
	flagInput       = "input"
	flagOutput      = "output"
	flagVTApiKey    = "apikey"
	flagExpireDays  = "expire"
	flagAction      = "action"
	flagProxy       = "proxy"
	flagDispatchers = "threads"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)

	fs.String(flagInput, "", "input filename")
	fs.String(flagOutput, "", "output filename")
	fs.String(flagVTApiKey, "", "VirusTotal API key")
	fs.Int(flagExpireDays, 30, "expire after (days)")
	fs.String(flagAction, "log", "action (block/log)")
	fs.String(flagProxy, "", "proxy URL")
	fs.Int(flagDispatchers, 5, "Simultaneous connections to Virus Total")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := viper.BindPFlags(fs); err != nil {
		log.Fatal(err)
	}
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()

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

//var apikey = flag.String("apikey", "", "VirusTotal API key")
//var filename = flag.String("filename", "", "filename")

/*
type Result struct {
	malicious bool
	hash      string
}
*/
/*
	func CheckFile(client *vt.Client, hash string, c chan Result) {
		log.Print("CheckFile ", hash)
		file, err := client.GetObject(vt.URL("files/%s", hash))
		if err != nil {
			log.Print(err)
			result := Result{
				malicious: false,
				hash:      err.Error(),
			}
			c <- result
			return
			log.Fatal(err)
		}
		category, err := file.GetString("last_analysis_results.TrendMicro.category")
		if err != nil {
			log.Fatal(err)
		}
		result := Result{
			malicious: category == "malicious",
			hash:      hash,
		}
		c <- result
		//result, err := file.Get("last_analysis_results.TrendMicro.result") //method
		//	fmt.Printf("File %s, %s, %s\n", file.ID(), category, sres)
	}
*/
func GetVTClient() *vt.Client {
	vtAPIKey := viper.GetString(flagVTApiKey)
	if vtAPIKey == "" {
		log.Fatalf("parameter is missing: %s", flagVTApiKey)
	}
	proxy := viper.GetString(flagProxy)
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.Fatalf("%s: %v", flagProxy, err)
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
	Configure()
	client := GetVTClient()
	input := os.Stdin
	inputFileName := viper.GetString(flagInput)
	if inputFileName == "" {
		log.Fatalf("parameter is missing: %s", flagInput)
	}
	if inputFileName != "-" {
		var err error
		input, err = os.Open(inputFileName)
		if err != nil {
			log.Fatal(err)
		}
	}
	if input != os.Stdin {
		log.Println("Loading input file")
	}
	lines, err := iocscsv.CSVReadFile(input, func(kind string) bool {
		return kind == "sha1"
	})
	if err != nil {
		log.Fatal(err)
	}
	input.Close()
	log.Printf("Loaded %d hashes", len(lines))
	log.Println("Get quota...")
	response, err := vtotal.GetVTQuota(client)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Monthly quota: %d", response.APIRequestsMonthly.User.Allowed)
	log.Printf("Daily quota: %d", response.APIRequestsDaily.User.Allowed)
	log.Printf("Hourly quota: %d", response.APIRequestsHourly.User.Allowed)
	t, d := response.EstimateFinishTimePublic(len(lines))
	log.Printf("Estimated script run time: %v", d.Round(time.Second))
	log.Printf("Estimated complete time: %v", t)
	quota := response.Quota()

	inboxCh := make(chan string)
	quotedCh := make(chan string)
	resultCh := make(chan string)

	quotaDispatch := QuotaDispatch(quota, inboxCh, quotedCh)
	vtDispatch := vtotal.NewVTDispatch(client, quota, quotedCh, resultCh)
	go quotaDispatch()
	dispatchers := viper.GetInt(flagDispatchers)
	log.Printf("Number of simultanious connections to Virus Total: %d", dispatchers)
	go vtDispatch.Run(dispatchers)
	var wg sync.WaitGroup
	wg.Add(1)
	go ResultsDispatch(resultCh, &wg)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		inboxCh <- line
	}
	close(inboxCh)
	wg.Wait()
}

func QuotaDispatch(q *vtotal.VTQuota, in, out chan string) func() {
	return func() {
		log.Println("Quota Dispatch")
		for h := range in {
			now := time.Now().UTC()
			t := q.EstimateCompleteTime(now, 1)
			sleep := t.Sub(now)
			if sleep != 0 {
				log.Printf("Sleep %v until %v", sleep, t)
				time.Sleep(sleep)
			}
			out <- h
		}
		close(out)
	}
}
func ResultsDispatch(in chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("Results Dispatch")
	output := os.Stdout
	outputFileName := viper.GetString(flagOutput)
	if outputFileName == "" {
		log.Fatalf("parameter is missing: %s", flagOutput)
	}
	if outputFileName != "-" {
		var err error
		output, err = os.Create(outputFileName)
		if err != nil {
			log.Fatal(err)
		}
		defer output.Close()
	}
	fmt.Fprintln(output, apex.CSVHeading)

	actionStr := "\"" + viper.GetString(flagAction) + "\""
	var action apex.ScanAction
	if err := (&action).UnmarshalJSON([]byte(actionStr)); err != nil {
		log.Fatal(err)
	}

	days := viper.GetInt(flagExpireDays)
	if days == 0 {
		log.Fatalf("parameter is missing: %s", flagExpireDays)
	}
	expire := time.Now().Add(time.Hour * 24 * time.Duration(days))

	for hash := range in {
		log.Printf("Result %s", hash)
		so := &apex.SO{
			Object:        hash,
			Type:          apex.ObjectTypeSHA1,
			Action:        action,
			ScanPrefilter: "",
			Notes:         "",
			ExirationDate: expire,
		}
		fmt.Fprintln(output, so)
	}
}
