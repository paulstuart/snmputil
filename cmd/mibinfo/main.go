package main

import (
	"flag"
	"os"

	"github.com/paulstuart/snmputil"
)

var (
	mibs string
	name string
)

func main() {
	flag.StringVar(&mibs, "m", mibs, "mibs to reference")
	flag.StringVar(&name, "f", name, "filename to save to")
	flag.Parse()
	// mib := "JUNIPER-IF-MIB:NS-ROOT-MIB"
	if len(name) > 0 {
		f, err := os.Create(name)
		if err != nil {
			panic(err)
		}
		snmputil.OIDList(mibs, f)
		f.Close()
		return
	}
	snmputil.OIDList(mibs, nil)
}
