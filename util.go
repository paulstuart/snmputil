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
	Debug, Verbose bool
	FromOID        = make(map[string]string)
	ToOID          = make(map[string]string)
	oidLookup      = make(map[string]int) // the index of the tuple
	tuples         = []OIDTuple{}
	multiName      = strings.Fields("Grouping Member Element Item")
	Done           = make(chan struct{})
)

const (
	ifName  = ".1.3.6.1.2.1.31.1.1.1.1"
	ifAlias = ".1.3.6.1.2.1.31.1.1.1.18"
)

// for saving the interpreted PDU value
//type Sender func(string, map[string]string, map[string]interface{}, time.Time) error
type Sender func(string, map[string]string, interface{}, time.Time) error

type Criteria struct {
	OID     string
	Tags    map[string]string
	Regexps []string
	Keep    bool // if true, keep matching otherwise omit
}

// OIDTuple is used to track the number of columns a table has
// It is used to determine if an OID is a table member
type OIDTuple struct {
	OID, Name string
	Entries   int
}

type Tuples []OIDTuple

type SnmpStats struct {
	LastError time.Time
	GetCnt    int64
	ErrCnt    int64
	Error     error
}

type StatsChan chan SnmpStats

type PDUFunc func(string, gosnmp.SnmpPDU) error

type ErrFunc func(error)

// numerical returns the parsed data type in its native form
func numerical(s string) (interface{}, error) {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return i, nil
	}
	return s, fmt.Errorf("not a number")
}

func (o Tuples) Len() int      { return len(o) }
func (o Tuples) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Tuples) Less(i, j int) bool {
	return strings.Compare(o[i].OID, o[j].OID) < 1
}

func say(fmt string, args ...interface{}) {
	if Verbose {
		log.Printf(fmt, args...)
	}
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
		FromOID[f[1]] = f[0]
		tuples = append(tuples, OIDTuple{f[1], f[0], 0})
	}
	// sort the tuples so we can find sequences of oids
	// with matching prefix
	sort.Sort(Tuples(tuples))
	for i := 0; i < len(tuples); i++ {
		t1 := tuples[i]
		cnt := 0
		for j := i + 1; j < len(tuples); j++ {
			t2 := tuples[j]
			if !strings.HasPrefix(t2.OID, t1.OID) {
				break
			}
			cnt++
		}
		tuples[i].Entries = cnt
	}
	for i, t := range tuples {
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

func Columns(profile Profile, oid string) (map[string]string, error) {
	lookup := make(map[string]string)
	client, err := NewClient(profile)
	if err == nil {
		err = BulkWalkAll(client, oid, SuffixValue(lookup))
	}
	client.Conn.Close()
	return lookup, err
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

// Finder finds the longest matching table entry for base, the given OID
// TODO: this scheme should probably be replaced by a radix tree
func Finder(base, oid string) (string, string, error) {
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	i, ok := oidLookup[base]
	if !ok {
		return base, "(unknown)", fmt.Errorf("not found: %s", base)
	}
	tuple := tuples[i]
	for k := i + tuple.Entries; k > i; k-- {
		if strings.HasPrefix(oid, tuples[k].OID) {
			return tuples[k].OID, tuples[k].Name, nil
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

// SuffixValue returns a map the OID suffixes and their respective names for each column of table
func SuffixValue(lookup map[string]string) PDUFunc {
	return func(root string, pdu gosnmp.SnmpPDU) error {
		switch pdu.Type {
		case gosnmp.OctetString:
			lookup[pdu.Name[len(root)+2:]] = string(pdu.Value.([]byte))
		case gosnmp.IPAddress:
			lookup[pdu.Name[len(root)+2:]] = pdu.Value.(string)
		default:
			log.Println("UNKNOWN TYPE:", pdu.Type, "VAL:", pdu.Value)
		}
		return nil
	}
}

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
	if err := BulkWalkAll(client, ifName, SuffixValue(columns)); err != nil {
		return nil, err
	}
	if err := BulkWalkAll(client, ifAlias, SuffixValue(aliases)); err != nil {
		return nil, err
	}

	return func(pdu gosnmp.SnmpPDU) error {
		// find the oid of a table entry, if it exists
		subOID, name, err := Finder(crit.OID, pdu.Name)
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

		say("OID:%s SUFFIX:%s COL:%s NAME:%s TYPE:%x VALUE:%v", crit.OID, suffix, column, name, pdu.Type, pdu.Value)
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
				if Verbose {
					log.Println(name, " - non numerical:", pdu.Type, "value", s)
				}
				pdu.Value = n
			}
		default:
			if Verbose {
				log.Println(name, " - unsupported type:", pdu.Type, "value", pdu.Value)
			}
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
	if Debug {
		client.Logger = log.New(os.Stderr, "", 0)
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

	// so we can poll immediately without waiting for first tick
	walk := func() {
		//fmt.Println("WALK OID:", oid)
		if err := client.BulkWalk(oid, walker); err != nil {
			if errFn != nil {
				//fmt.Println("WALK ERR:", err)
				errFn(err)
			}
			stats.ErrCnt++
			stats.LastError = time.Now()
		} else {
			stats.GetCnt++
		}
	}

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
