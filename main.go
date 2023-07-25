package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/mpkondrashin/tmdetect/apex"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TODO:
// indicatros from previous time
// output 0 format to import to Apex Central
// Operate using pipe

const (
	EnvPrefix = "TMDETECT"
)

const (
	ConfigFileName = "config"
	ConfigFileType = "yaml"
)

const (
	flagInput      = "input"
	flagOutput     = "output"
	flagVTApiKey   = "apikey"
	flagExpireDays = "expire"
	flagAction     = "action"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)

	fs.String(flagInput, "", "input filename")
	fs.String(flagOutput, "", "output filename")
	fs.String(flagVTApiKey, "", "VirusTotal API key")
	fs.Int(flagExpireDays, 30, "expire after (days)")
	fs.String(flagAction, "log", "action (block/log)")
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

var apikey = flag.String("apikey", "", "VirusTotal API key")
var filename = flag.String("filename", "", "filename")

type Result struct {
	malicious bool
	hash      string
}

func CheckFile(client *vt.Client, hash string, c chan Result) {
	log.Print("CheckFile ", hash)
	file, err := client.GetObject(vt.URL("files/%s", hash))
	if err != nil {
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

func main() {
	Configure()
	vtAPIKey := viper.GetString(flagVTApiKey)
	if vtAPIKey == "" {
		log.Fatalf("parameter is missing: %s", flagVTApiKey)
	}
	client := vt.NewClient(vtAPIKey)

	actionStr := "\"" + viper.GetString(flagAction) + "\""
	var action apex.ScanAction
	if err := (&action).UnmarshalJSON([]byte(actionStr)); err != nil {
		log.Fatal(err)
	}

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
	lines, err := csvReadFile(input)
	if err != nil {
		log.Fatal(err)
	}
	input.Close()
	log.Printf("Loaded %d lines", len(lines))

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
	result := make(chan Result)
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		count++
		go CheckFile(client, line, result)
	}
	days := viper.GetInt(flagExpireDays)
	expire := time.Now().Add(time.Hour * 24 * time.Duration(days))
	for i := 0; i < count; i++ {
		r := <-result
		percent := (i + 1) * 100 / count
		log.Printf("Result %d%%, %v, %s", percent, r.malicious, r.hash)
		if r.malicious {
			continue
		}
		so := &apex.SO{
			Object:        r.hash,
			Type:          apex.ObjectTypeSHA1,
			Action:        action,
			ScanPrefilter: "",
			Notes:         "",
			ExirationDate: expire,
		}
		fmt.Fprintln(output, so)
	}
}
