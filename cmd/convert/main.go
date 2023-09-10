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
	flagKind       = "kind"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)
	fs.String(flagInput, "", "input filename")
	fs.String(flagOutput, "", "output filename")
	fs.String(flagAction, "log", "action (log/block)")
	fs.Int(flagExpireDays, 30, "expire after (days)")
	fs.String(flagNote, "", "note")
	fs.String(flagKind, "ip,domain,url,sha1", "comma separated list of types to convert (url,ip-dst,hostname,domain,sha1)")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := viper.BindPFlags(fs); err != nil {
		log.Fatal(err)
	}
}

var translateType = map[iocscsv.ThreatType]apex.ObjectType{
	iocscsv.ThreatTypeUrl:      apex.ObjectTypeURL,
	iocscsv.ThreatTypeIp_dst:   apex.ObjectTypeIP,
	iocscsv.ThreatTypeHostname: apex.ObjectTypeDomain,
	iocscsv.ThreatTypeDomain:   apex.ObjectTypeDomain,
	iocscsv.ThreatTypeSha1:     apex.ObjectTypeSHA1,
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

	kinds := getKinds(viper.GetString(flagKind))

	actionStr := "\"" + viper.GetString(flagAction) + "\""
	var action apex.ScanAction
	if err := (&action).UnmarshalJSON([]byte(actionStr)); err != nil {
		log.Fatal(err)
	}

	days := viper.GetInt(flagExpireDays)
	//expire := time.Now().Add(time.Hour * 24 * time.Duration(days))

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

	if input != os.Stdin {
		log.Printf("Loading input file %s", inputFileName)
	}
	if output != os.Stdout {
		log.Printf("Saving result to %s", outputFileName)
	}
	countInput := 0
	countOutput := 0
	err := iocscsv.CSVIterate(input, func(ioc *iocscsv.IoC) error {
		countInput++
		t, ok := translateType[ioc.Type]
		if !ok {
			return nil
		}
		_, ok = kinds[t]
		if !ok {
			return nil
		}
		so := &apex.SO{
			Object:        ioc.Content,
			Type:          t,
			Action:        action,
			ScanPrefilter: "",
			Notes:         viper.GetString(flagNote),
			ExirationDate: ioc.Time.Add(time.Hour * 24 * time.Duration(days)),
		}
		fmt.Fprintln(output, so)
		countOutput++
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	input.Close()
	log.Printf("Loaded %d IoCs", countInput)

	log.Printf("Saved %d IoCs", countOutput)
}

func getKinds(commaSeparatedList string) map[apex.ObjectType]struct{} {
	result := make(map[apex.ObjectType]struct{})
	for _, kind := range strings.Split(commaSeparatedList, ",") {
		var ot apex.ObjectType
		if err := (&ot).UnmarshalJSON([]byte("\"" + kind + "\"")); err != nil {
			log.Fatal(err)
		}
		result[ot] = struct{}{}
	}
	return result
}
