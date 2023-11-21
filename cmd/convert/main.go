package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/mpkondrashin/tmdetect/pkg/apex"
	"github.com/mpkondrashin/tmdetect/pkg/csvtoso"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	flagInput      = "input"
	flagAction     = "action"
	flagExpireDays = "expire"
	flagNote       = "note"
)

func Configure() {
	fs := pflag.NewFlagSet("TMDetect", pflag.ExitOnError)
	fs.String(flagInput, "", "input filename")
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
	inputFileName := viper.GetString(flagInput)
	if inputFileName == "" {
		log.Fatalf("parameter is missing: %s", flagInput)
	}
	actionStr := "\"" + viper.GetString(flagAction) + "\""
	var action apex.ScanAction
	if err := (&action).UnmarshalJSON([]byte(actionStr)); err != nil {
		log.Fatal(err)
	}

	days := viper.GetInt(flagExpireDays)
	udsoFileName, appControlFileName := OutputFileNames(inputFileName)

	outputUDSO, err := os.Create(udsoFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputUDSO.Close()
	fmt.Fprintln(outputUDSO, apex.CSVHeading)

	outputAC, err := apex.ACHashCreate(appControlFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputAC.Close()

	countInput := 0
	countOutputUDSO := 0
	countOutputSHA256 := 0
	expireDate := time.Now().Add(time.Hour * 24 * time.Duration(days))
	notes := viper.GetString(flagNote)
	log.Printf("Processing %s", inputFileName)
	log.Printf("Expire date for Custom Intelligence: %v", expireDate.Format("02.01.2006"))

	err = csvtoso.IterateSO(inputFileName, func(content string, typ apex.ObjectType) error {
		countInput++
		if typ == apex.ObjectTypeSha256 {
			ac := &apex.SOiAC{
				SHA:      content,
				FileName: notes,
			}
			outputAC.WriteHash(ac)
			countOutputSHA256++
		} else {
			so := &apex.SO{
				Object:        content,
				Type:          typ,
				Action:        action,
				ScanPrefilter: "",
				Notes:         viper.GetString(flagNote),
				ExirationDate: expireDate,
			}
			fmt.Fprintln(outputUDSO, so)
			countOutputUDSO++
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Parsed %d IoCs", countInput)
	log.Printf("Saving UDSO result to %s", udsoFileName)
	log.Printf("Saving AppControl result to %s", appControlFileName)
	log.Printf("Saved %d IoCs for Custom Intelligence", countOutputUDSO)
	log.Printf("Saved %d SHA256 for Application Control", countOutputSHA256)
}

func fileNameWithoutExt(fileName string) string {
	return fileName[:len(fileName)-len(filepath.Ext(fileName))]
}

func OutputFileNames(inputFileName string) (string, string) {
	base := fileNameWithoutExt(inputFileName)
	return base + "_custom_intelligence.csv", base + "_application_control.zip"
}
