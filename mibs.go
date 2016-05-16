package snmputil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/soniah/gosnmp"
)

// MibInfo contains all the details of a MIB entry
type MibInfo struct {
	Name        string
	OID         string
	Syntax      string
	Default     string
	Hint        string
	Index       string
	Units       string
	Access      string
	Augments    string
	Status      string
	Description string
}

type oidInfo struct {
	Name  string
	Index int
	Fn    pduReader
}

type mibFunc func(MibInfo)

var (
	oidBase   = make(map[string]oidInfo)
	dupeNames = make(map[string]string)

	//lookupOID is a lookup table to find the dotted form of a symbolic name
	lookupOID = make(map[string]string)

	digi = regexp.MustCompile("([0-9]+)(\\.\\.([0-9]+))?")
	look = regexp.MustCompile("([a-zA-Z]+)\\(([0-9]+)\\)")
	list = regexp.MustCompile("([a-zA-Z]+)\\s+{(.*)}")
)

func (o oidInfo) String() string {
	return o.Name[o.Index:]
}

func oidReader(m MibInfo) {
	index := strings.Index(m.Name, "::")
	if index > 0 {
		index += 2
	}
	oid := "." + m.OID
	name := m.Name[index:]
	if o, ok := lookupOID[name]; ok {
		index = 0
		dupeNames[name] = o
		name = m.Name
	} else {
		lookupOID[name] = oid
	}
	oidBase[oid] = oidInfo{Name: m.Name, Index: index, Fn: pduFunc(m)}
	rtree, _, _ = rtree.Insert([]byte(oid), name)
}

// pduFunc returns a pduReader based upon the OID type and hints
func pduFunc(m MibInfo) pduReader {
	if m.Hint == "2d-1d-1d,1d:1d:1d.1d,1a1d:1d" {
		return dateTime
	}
	if fn := numberType(m.Syntax); fn != nil {
		return fn
	}
	return pduType
}

// LoadMibs will load the entries for the MIBs specified
func LoadMibs(mib string) error {
	if err := OIDTranslate(mib, oidReader); err != nil {
		return err
	}
	return nil
}

func mibFile(f *os.File, fn mibFunc) error {
	dec := json.NewDecoder(f)
	for {
		var m MibInfo
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		fn(m)
	}
	return nil
}

func loadMibInfo(filename string, fn mibFunc) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return mibFile(f, fn)
}

// CachedMibInfo will load saved mib data or create it
// if the file does not exist
func CachedMibInfo(filename, mibs string) error {
	f, err := os.Open(filename)
	if err != nil {
		if f, err = os.Create(filename); err != nil {
			return err
		}
		if err = OIDList(mibs, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return loadMibInfo(filename, oidReader)
}

func snmpTranslate(mib, oid string) []string {
	out, err := exec.Command("snmptranslate", "-Td", "-OS", "-m", mib, oid).Output()
	if err != nil {
		log.Fatal(err)
	}
	lines := make([]string, 0, 32)
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		lines = append(lines, strings.TrimSpace(s.Text()))
	}
	return lines
}

func printMibInfo(w io.Writer) mibFunc {
	return func(m MibInfo) {
		b, err := json.MarshalIndent(m, " ", "  ")
		if err != nil {
			log.Println("error:", err)
		}
		fmt.Fprintln(w, string(b))
	}
}

// OIDList will generate a list of OIDs and their details
func OIDList(mib string, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	err := OIDTranslate(mib, printMibInfo(w))
	return err
}

// OIDTranslate will apply detailed OID info to fn
func OIDTranslate(mib string, fn mibFunc) error {
	if len(mib) == 0 {
		mib = "ALL"
	}

	var (
		pipeIn  = make(chan string)
		pipeOut = make(chan MibInfo, 32000)
		wg      sync.WaitGroup
	)

	go func() {
		for m := range pipeOut {
			fn(m)
		}
	}()

	cmd := exec.Command("snmptranslate", "-Tz", "-On", "-m", mib)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			for oid := range pipeIn {
				lines := snmpTranslate(mib, oid)
				pipeOut <- parseMibInfo(oid, lines)
			}
			wg.Done()
		}()
	}

	s := bufio.NewScanner(stdout)
	for s.Scan() {
		info := strings.Fields(s.Text())
		pipeIn <- info[1][1 : len(info[1])-1]
	}

	if err := cmd.Wait(); err != nil {
		return err
	}
	close(pipeIn)
	wg.Wait()
	close(pipeOut)
	return nil
}

// parseMibInfo will translate output from snmptranslate into structured data
func parseMibInfo(oid string, lines []string) MibInfo {
	m := MibInfo{OID: oid, Name: lines[0]}
	d := make([]string, 0, 32)
	for i := 2; i < len(lines); i++ {
		line := lines[i]
		if len(d) > 0 {
			if !strings.HasPrefix(line, "::=") {
				d = append(d, line)
			}
			continue
		}
		bits := strings.Split(line, "\t")
		if len(bits) < 2 {
			continue
		}
		s := bits[1]
		if strings.HasPrefix(s, "--") {
			continue
		}
		if strings.HasPrefix(s, `"`) && !strings.HasSuffix(s, `"`) {
			for i++; i < len(lines); i++ {
				line := lines[i]
				s += line
				if strings.HasSuffix(line, `"`) {
					break
				}
			}
		}
		str := strings.Trim(s, `"`)
		switch bits[0] {
		case "SYNTAX":
			m.Syntax = str
		case "DEFVAL":
			m.Default = str
		case "DISPLAY-HINT":
			m.Hint = str
		case "MAX-ACCESS":
			m.Access = str
		case "STATUS":
			m.Status = str
		case "UNITS":
			m.Units = str
		case "INDEX":
			m.Index = str
		case "AUGMENTS":
			m.Augments = str
		case "DESCRIPTION":
			d = append(d, str)
		}
	}
	m.Description = strings.Trim(strings.Join(d, "\n"), `"`)
	return m
}

// looker will parse mib SYNTAX, e.g.,
// "BITS {sunday(0), monday(1), tuesday(2), wednesday(3), thursday(4), friday(5), saturday(6)}"
func looker(s string) (kind string, m map[int]string) {
	a := list.FindStringSubmatch(s)
	if len(a) == 3 {
		m = make(map[int]string)
		kind = a[1]
		s := look.FindAllStringSubmatch(a[2], -1)
		for _, x := range s {
			i, _ := strconv.Atoi(x[2])
			m[i] = x[1]
		}
	}
	return
}

func numberType(s string) pduReader {
	if len(s) == 0 {
		return nil
	}
	kind, m := looker(s)
	switch kind {
	case "BITS":
		return bitFormatter(m)
	case "INTEGER":
		return intFormatter(m)
	}
	return nil
}

func bitFormatter(m map[int]string) pduReader {
	return func(pdu gosnmp.SnmpPDU) (interface{}, error) {
		fmt.Println("BITS FOR:", pdu.Name)
		data := pdu.Value.([]byte)
		names := make([]string, 0, len(data)*8)
		cnt := 0
		for _, d := range data {
			for i := 0; i < 8; i++ {
				if (d & 0x80) == 0x80 {
					if name, ok := m[cnt]; ok {
						names = append(names, name)
					} else {
						return pdu.Value, fmt.Errorf("no label found for index:%d", cnt)
					}
				}
				d <<= 1
				cnt++
			}
		}
		return strings.Join(names, ","), nil
	}
}

func intFormatter(m map[int]string) pduReader {
	return func(pdu gosnmp.SnmpPDU) (interface{}, error) {
		v := pdu.Value.(int)
		if name, ok := m[v]; ok {
			return name, nil
		}
		return pdu.Value, fmt.Errorf("no label found for index:%d", v)
	}
}
