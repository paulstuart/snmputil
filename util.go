// Package snmputil provides helper routines for gosnmp

// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package snmputil

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/soniah/gosnmp"
)

var (
	// Debug will log snmp debugging output if set
	Debug *log.Logger
	// Verbose will log output if set
	Verbose *log.Logger
	// ToOID is a lookup table to find the dotted form of a symbolic name
	ToOID = make(map[string]string)
	// Done will terminate all polling processes if closed
	Done      = make(chan struct{})
	oidLookup = make(map[string]int) // the index of the tuple
	table     = []oidTuple{}
	// how to break up column indexes with multiple elements
	multiName = strings.Fields("Grouping Member Element Item")
)

const (
	ifName  = ".1.3.6.1.2.1.31.1.1.1.1"
	ifAlias = ".1.3.6.1.2.1.31.1.1.1.18"
)

// Sender will send the interpreted PDU value to be saved or whathaveyou
type Sender func(string, map[string]string, interface{}, time.Time) error

// Criteria specifies what is to query and what to keep
type Criteria struct {
	OID     string            // OID can be dotted string or symbolic name
	Tags    map[string]string // any additional tags to associate
	Regexps []string          // filter resulting entries
	Keep    bool              // keep if resulting name matches, otherwise omit
}

// SnmpStats tracks SNMP request activity
type SnmpStats struct {
	LastError time.Time
	GetCnt    int64
	ErrCnt    int64
	Error     error
}

// StatsChan is used to request SnmpStats from a polling process
type StatsChan chan SnmpStats

// PDUFunc takes the original OID and a resulting SNMP packet to process
type PDUFunc func(string, gosnmp.SnmpPDU) error

// ErrFunc accepts SNMP errors for processing
type ErrFunc func(error)

// oidTuple is used to track the number of columns a table has
// It is used to determine if an OID is a table member
type oidTuple struct {
	OID, Name string
	Entries   int
}

// Tuples is a list of tuples containing OID table info
type Tuples []oidTuple

func (o Tuples) Len() int      { return len(o) }
func (o Tuples) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Tuples) Less(i, j int) bool {
	return strings.Compare(o[i].OID, o[j].OID) < 1
}

func say(fmt string, args ...interface{}) {
	if Verbose != nil {
		Verbose.Printf(fmt, args...)
	}
}

// numerical returns the parsed data type in its numeric form
func numerical(s string) (interface{}, error) {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return i, nil
	}
	return s, fmt.Errorf("not a number")
}

// LoadOIDs reads a file of OIDs and their symbolic names
func LoadOIDs(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 2 {
			continue
		}
		ToOID[f[0]] = f[1]
		table = append(table, oidTuple{f[1], f[0], 0})
	}
	// sort the tuples so we can find sequences of oids
	// with matching prefix
	sort.Sort(Tuples(table))
	for i := 0; i < len(table); i++ {
		t1 := table[i]
		cnt := 0
		for j := i + 1; j < len(table); j++ {
			t2 := table[j]
			if !strings.HasPrefix(t2.OID, t1.OID) {
				break
			}
			cnt++
		}
		table[i].Entries = cnt
	}
	for i, t := range table {
		oidLookup[t.OID] = i
	}
	return scanner.Err()
}

// LoadOIDFile is a helper routine to load OID descriptions from a file
func LoadOIDFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return LoadOIDs(f)
}

// makeString converts ascii octets into a string
func makeString(bits []string) string {
	chars := make([]byte, len(bits))
	for i, bit := range bits {
		n, _ := strconv.Atoi(bit)
		chars[i] = byte(n)
	}
	return string(chars)
}

// oidStrings converts ascii octets into an array of words
func oidStrings(in string) []string {
	words := []string{}
	bits := strings.Split(in, ".")
	for i := 0; i < len(bits); i++ {
		cnt, _ := strconv.Atoi(bits[i])
		end := i + cnt + 1
		if i > len(bits) || i >= end {
			break
		}
		if end > len(bits) {
			end = len(bits)
		}
		word := makeString(bits[i+1 : end])
		words = append(words, word)
		i += cnt
	}
	return words
}

// finder finds the longest matching table entry for base, the given OID
// TODO: this scheme should be replaced by a radix tree
func finder(base, oid string) (string, string, error) {
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	i, ok := oidLookup[base]
	if !ok {
		return base, "(unknown)", fmt.Errorf("not found: %s", base)
	}
	tuple := table[i]
	for k := i + tuple.Entries; k > i; k-- {
		if strings.HasPrefix(oid, table[k].OID) {
			return table[k].OID, table[k].Name, nil
		}
	}
	return base, tuple.Name, nil
}

// Octets converts ascii octets into a byte array
func stringToOctets(in string) []byte {
	if strings.HasPrefix(in, ".") {
		in = in[1:]
	}
	bits := strings.Split(in, ".")
	reply := make([]byte, len(bits))
	for i, bit := range bits {
		b, _ := strconv.Atoi(bit)
		reply[i] = byte(b)
	}
	return reply
}

// Octets converts ascii octets into a byte array
func octetsToString(in []byte) string {
	buf := make([]string, len(in))
	for i, bit := range in {
		buf[i] = fmt.Sprintf("%d", bit)
	}
	return strings.Join(buf, ".")
}

// suffixValue returns a map the OID suffixes and their respective names for each column of table
func suffixValue(lookup map[string]string) PDUFunc {
	return func(root string, pdu gosnmp.SnmpPDU) error {
		switch pdu.Type {
		case gosnmp.OctetString:
			lookup[pdu.Name[len(root)+2:]] = string(pdu.Value.([]byte))
		case gosnmp.IPAddress:
			lookup[pdu.Name[len(root)+2:]] = pdu.Value.(string)
		default:
			say("UNKNOWN TYPE: %x VALUE: %v\n", pdu.Type, pdu.Value)
		}
		return nil
	}
}

// BulkColumns returns a WalkFunc that will process results from a bulkwalk
func BulkColumns(client *gosnmp.GoSNMP, crit Criteria, sender Sender) (gosnmp.WalkFunc, error) {
	filterNames := []*regexp.Regexp{}
	for _, n := range crit.Regexps {
		re, err := regexp.Compile(n)
		if err != nil {
			return nil, err
		}
		filterNames = append(filterNames, re)
	}

	columns := make(map[string]string)
	aliases := make(map[string]string)
	if err := BulkWalkAll(client, ifName, suffixValue(columns)); err != nil {
		return nil, err
	}
	if err := BulkWalkAll(client, ifAlias, suffixValue(aliases)); err != nil {
		return nil, err
	}

	return func(pdu gosnmp.SnmpPDU) error {
		// find the oid of a table entry, if it exists
		subOID, name, err := finder(crit.OID, pdu.Name)
		if err != nil {
			return err
		}

		filtered := crit.Keep
		for _, r := range filterNames {
			if r.MatchString(name) {
				if crit.Keep {
					filtered = false
					break
				}
				say("Omitting name: %s (%s)\n", name, subOID)
				return nil
			}
		}
		if filtered {
			say("Not keeping name: %s (%s)\n", name, subOID)
			return nil
		}

		var column, alias string
		suffix := pdu.Name[len(subOID)+2:]
		group := oidStrings(suffix)

		// interface names/aliases only apply to OIDs starting with 'if'
		if strings.HasPrefix(name, "if") {
			column = columns[suffix]
			alias = aliases[suffix]
		}
		if len(group) == 0 && len(column) == 0 && suffix != "0" {
			column = makeString(strings.Split(suffix, "."))
		}

		say("OID:%s SUFFIX:%s COL:%s NAME:%s TYPE:%x VALUE:%v\n", crit.OID, suffix, column, name, pdu.Type, pdu.Value)
		t := map[string]string{}
		if len(column) > 0 {
			t["Column"] = column
		}
		if len(alias) > 0 {
			t["Alias"] = alias
		}
		if len(group) > 0 && len(group[0]) > 0 {
			t["Grouping"] = group[0]
		}
		if len(group) > 1 && len(group[1]) > 0 {
			t["Member"] = group[1]
		}
		if len(group) > 3 && len(group[1]) > 0 {
			t["Element"] = group[2]
		}

		// copy tag values so we don't modify original tags map
		for k, v := range crit.Tags {
			t[k] = v
		}
		switch pdu.Type {
		case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Counter64, gosnmp.Uinteger32:
		case gosnmp.IPAddress:
		case gosnmp.OctetString:
			s := string(pdu.Value.([]uint8))
			if n, err := numerical(s); err != nil {
				say("%s (%x) - non numerical: %s\n", name, pdu.Type, s)
				pdu.Value = n
			}
		default:
			say(name, "%s - unsupported type: %x value: %v\n", name, pdu.Type, pdu.Value)
			return nil
		}
		return sender(name, t, pdu.Value, time.Now())
	}, nil
}

// GetOID will return the OID representing name
func GetOID(oid string) (string, error) {
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	if strings.HasPrefix(oid, "1.") {
		return oid, nil
	}
	fixed, ok := ToOID[oid]
	if !ok {
		return oid, fmt.Errorf("no OID found for %s", oid)
	}
	return fixed, nil
}

// BulkWalkAll applies bulk walk results to fn once all values returned (synchronously)
func BulkWalkAll(client *gosnmp.GoSNMP, oid string, fn PDUFunc) error {
	pdus, err := client.BulkWalkAll(oid)
	if err != nil {
		return err
	}
	for _, pdu := range pdus {
		if err := fn(oid, pdu); err != nil {
			return err
		}
	}
	return nil
}

// InterfaceNames will apply the interface name and oid to the given fn
func InterfaceNames(p Profile, fn func(string, string)) error {
	client, err := NewClient(p)
	if err != nil {
		return err
	}

	defer client.Conn.Close()
	return BulkWalkAll(client, ifName,
		func(root string, pdu gosnmp.SnmpPDU) error {
			switch pdu.Type {
			case gosnmp.OctetString:
				fn(pdu.Name, string(pdu.Value.([]byte)))
			}
			return nil
		})
}

// Bulkwalker will do a bulkwalk on the device specified in the Profile
func Bulkwalker(p Profile, crit Criteria, sender Sender, freq int, errFn ErrFunc, status chan StatsChan) error {
	client, err := NewClient(p)
	if err != nil {
		return err
	}
	crit.OID, err = GetOID(crit.OID)
	if err != nil {
		return err
	}
	if crit.Tags == nil {
		crit.Tags = make(map[string]string)
	}
	crit.Tags["Host"] = client.Target
	if Debug != nil {
		client.Logger = Debug
	}
	walker, err := BulkColumns(client, crit, sender)
	if err != nil {
		return err
	}
	go Poller(client, crit.OID, freq, walker, errFn, status)
	return nil
}

// Poller will make snmp requests indefinitely
func Poller(client *gosnmp.GoSNMP, oid string, freq int, walker gosnmp.WalkFunc, errFn ErrFunc, status chan StatsChan) {

	stats := SnmpStats{}

	c := time.Tick(time.Duration(freq) * time.Second)

	walk := func() {
		if err := client.BulkWalk(oid, walker); err != nil {
			if errFn != nil {
				errFn(err)
			}
			stats.ErrCnt++
			stats.LastError = time.Now()
		} else {
			stats.GetCnt++
		}
	}

	// poll immediately without waiting for first tick
	walk()

	for {
		select {
		case _ = <-c:
			walk()
		case s := <-status:
			s <- stats
		case _ = <-Done:
			client.Conn.Close()
			return
		}
	}
}
