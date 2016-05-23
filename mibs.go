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
	"runtime"
	"strconv"
	"strings"
	"sync"

	radix "github.com/hashicorp/go-immutable-radix"
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
type pduReader func(gosnmp.SnmpPDU) (interface{}, error)

var (
	oidBase   = make(map[string]oidInfo)
	dupeNames = make(map[string]string)

	// oidLookup is a lookup table to find the dotted form of a symbolic name
	lookupOID = make(map[string]string)

	digi = regexp.MustCompile("([0-9]+)(\\.\\.([0-9]+))?")
	look = regexp.MustCompile("([a-zA-Z]+)\\(([0-9]+)\\)")
	list = regexp.MustCompile("([a-zA-Z]+)\\s+{(.*)}")

	snmptranslate, _ = exec.LookPath("snmptranslate")
	mu               sync.Mutex
)

func (o oidInfo) String() string {
	return o.Name[o.Index:]
}

// rootOID when given a map of names and their OIDs
// returns a function that returns the root OID
// of a full OID with index
func rootOID(m map[string]string) func(string) string {
	tree := radix.New()
	for name, oid := range m {
		tree, _, _ = tree.Insert([]byte(oid), name)
	}

	return func(oid string) string {
		if sub, _, ok := tree.Root().LongestPrefix([]byte(oid)); ok {
			return string(sub)
		}
		return ""
	}
}

// oidReader adds MibInfo to a database of OIDs and their handlers
func oidReader(m MibInfo) {
	index := strings.Index(m.Name, "::")
	if index > 0 {
		index += 2
	}
	oid := m.OID
	if oid[0] != '.' {
		oid = "." + oid
	}
	name := m.Name[index:]
	mu.Lock()
	if o, ok := lookupOID[name]; ok {
		index = 0
		dupeNames[name] = o
		name = m.Name
	} else {
		lookupOID[name] = oid
	}
	mu.Unlock()
	oidBase[oid] = oidInfo{Name: m.Name, Index: index, Fn: pduFunc(m)}
	rtree, _, _ = rtree.Insert([]byte(oid), name)
}

// pduFunc returns a pduReader based upon the OID type and hints
// TODO: add other hinted formats functions here
func pduFunc(m MibInfo) pduReader {
	if m.Hint == "2d-1d-1d,1d:1d:1d.1d,1a1d:1d" {
		return dateTime
	}
	if fn := numberType(m.Syntax); fn != nil {
		return fn
	}
	return pduType
}

// LoadMibs loads the entries for the MIBs specified
func LoadMibs(mib string) error {
	return mibTranslate(mib, oidReader)
}

// mibFile decodes a stream
func mibFile(r io.Reader, fn mibFunc) error {
	dec := json.NewDecoder(r)
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

// loadMibInfo applys fn to all the records in filename
func loadMibInfo(filename string, fn mibFunc) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return mibFile(f, fn)
}

// CachedMibInfo loads saved mib data or creates it
// if the file does not exist
func CachedMibInfo(filename, mibs string) error {
	f, err := os.Open(filename)
	if err != nil {
		if f, err = os.Create(filename); err != nil {
			return err
		}
		if err = OIDList(mibs, nil, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return loadMibInfo(filename, oidReader)
}

// printMibInfo returns a prettyprint handler
func printMibInfo(w io.Writer) mibFunc {
	return func(m MibInfo) {
		if m.Status != "obsolete" {
			b, err := json.MarshalIndent(m, " ", "  ")
			if err != nil {
				log.Println("error:", err)
			}
			fmt.Fprintln(w, string(b))
		}
	}
}

// OIDList generates a list of OIDs and their details
func OIDList(mib string, oids []string, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	if len(oids) > 0 {
		return oidTranslate(mib, oids, printMibInfo(w))
	}
	return mibTranslate(mib, printMibInfo(w))
}

// oidNames returns the OIDs and their names from the mib(s) specified
func oidNames(mib string) (map[string]string, error) {
	m := make(map[string]string)
	if len(snmptranslate) == 0 {
		return m, fmt.Errorf("snmptranslate is not found in current PATH")
	}
	if len(mib) == 0 {
		mib = "ALL"
	}

	cmd := exec.Command(snmptranslate, "-Tz", "-On", "-m", mib)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return m, err
	}
	if err := cmd.Start(); err != nil {
		return m, err
	}

	s := bufio.NewScanner(stdout)
	for s.Scan() {
		info := strings.Fields(s.Text())
		name := strings.Trim(info[0], `"`)
		oid := strings.Trim(info[1], `"`)
		m[name] = "." + oid
	}

	return m, cmd.Wait()
}

// oidTranslate applies detailed OID info to fn
func oidTranslate(mib string, oids []string, fn mibFunc) error {
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

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			for oid := range pipeIn {
				m, err := parseMibInfo(mib, oid)
				if err != nil {
					log.Fatal(err)
				}
				pipeOut <- *m
			}
			wg.Done()
		}()
	}

	for _, oid := range oids {
		pipeIn <- oid
	}

	close(pipeIn)
	wg.Wait()
	close(pipeOut)
	return nil
}

// mibTranslate applies detailed OID info to fn
func mibTranslate(mib string, fn mibFunc) error {
	info, err := oidNames(mib)
	if err != nil {
		return err
	}
	oids := make([]string, 0, len(info))
	for _, v := range info {
		oids = append(oids, v)
	}
	return oidTranslate(mib, oids, fn)
}

// parseMibInfo translates output from snmptranslate into structured data
func parseMibInfo(mib, oid string) (*MibInfo, error) {
	out, err := exec.Command(snmptranslate, "-Td", "-OS", "-m", mib, oid).Output()
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, 32)
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		lines = append(lines, strings.TrimSpace(s.Text()))
	}

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
	return &m, nil
}

// looker parses mib SYNTAX, e.g.,
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
