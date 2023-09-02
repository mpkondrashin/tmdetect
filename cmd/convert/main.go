package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/mpkondrashin/tmdetect/pkg/apex"
	"github.com/mpkondrashin/tmdetect/pkg/iocscsv"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	flagInput      = "input"
	flagOutput     = "output"
	flagAction     = "action"
	flagExpireDays = "expire"
	flagNote       = "note"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)
	fs.String(flagInput, "", "input filename")
	fs.String(flagOutput, "", "output filename")
	fs.String(flagAction, "log", "action (log/block)")
	fs.Int(flagExpireDays, 30, "expire after (days)")
	fs.String(flagNote, "", "note")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := viper.BindPFlags(fs); err != nil {
		log.Fatal(err)
	}
}

func main() {
	Configure()
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

	actionStr := "\"" + viper.GetString(flagAction) + "\""
	var action apex.ScanAction
	if err := (&action).UnmarshalJSON([]byte(actionStr)); err != nil {
		log.Fatal(err)
	}

	days := viper.GetInt(flagExpireDays)
	expire := time.Now().Add(time.Hour * 24 * time.Duration(days))

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

	for _, hash := range lines {
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		//log.Printf("Result %s", hash)
		so := &apex.SO{
			Object:        hash,
			Type:          apex.ObjectTypeSHA1,
			Action:        action,
			ScanPrefilter: "",
			Notes:         viper.GetString(flagNote),
			ExirationDate: expire,
		}
		fmt.Fprintln(output, so)
	}
	log.Printf("Saved %d hashes", len(lines))
}
