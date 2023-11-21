package apex

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

const AppControlCSVHeading = "Version:V1\r\n"

type SOiAC struct {
	SHA      string
	FileName string
}

func (s *SOiAC) String() string {
	return fmt.Sprintf("%s,%s", s.SHA, s.FileName)
}

type ACHash struct {
	f         *os.File
	zipWriter *zip.Writer
	csvWriter io.Writer
}

func ACHashCreate(fileName string) (*ACHash, error) {
	a := &ACHash{}
	var err error
	a.f, err = os.Create(fileName)
	if err != nil {
		return nil, err
	}
	a.zipWriter = zip.NewWriter(a.f)
	a.csvWriter, err = a.zipWriter.Create("appcontrol.csv")
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fprint(a.csvWriter, AppControlCSVHeading)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *ACHash) WriteHash(h *SOiAC) error {
	_, err := fmt.Fprintf(a.csvWriter, "%v\r\n", h)
	return err
}

func (a *ACHash) Close() error {
	a.zipWriter.Close()
	return a.f.Close()
}
