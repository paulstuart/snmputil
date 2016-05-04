// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	radix "github.com/hashicorp/go-immutable-radix"
	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

var (
	debugging *log.Logger

	// lookupOID is a lookup table to find the dotted form of a symbolic name
	lookupOID = make(map[string]string)

	// done will terminate all polling processes if closed
	done = make(chan struct{})
	// how to break up column indexes with multiple elements
	multiName = strings.Fields("Grouping Member Element Item")
	rtree     = radix.New()
)

const (
	ifName  = ".1.3.6.1.2.1.31.1.1.1.1"
	ifAlias = ".1.3.6.1.2.1.31.1.1.1.18"
)

// Counter32 is 32 bit SNMP counter
type Counter32 uint32

// Counter64 is 32 bit SNMP counter
type Counter64 uint64

// Sender will send the interpreted PDU value to be saved or whathaveyou
type Sender func(string, map[string]string, interface{}, time.Time) error

// Criteria specifies what is to query and what to keep
type Criteria struct {
	OID     string            // OID can be dotted string or symbolic name
	Tags    map[string]string // any additional tags to associate
	Regexps []string          // filter resulting entries
	Keep    bool              // keep if resulting name matches, otherwise omit
	OIDTag  bool              // add OID as a tag
	Aliases map[string]string // optional column aliases
}

// ErrFunc processes error and may be nil if desired
type ErrFunc func(error)

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

// loadOIDs reads in a stream of OIDs and their symbolic names
func loadOIDs(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 2 {
			continue
		}
		// snmptranslate isn't providing leading dot
		if f[1][:1] != "." {
			f[1] = "." + f[1]
		}
		lookupOID[f[0]] = f[1]
		rtree, _, _ = rtree.Insert([]byte(f[1]), f[0])
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
	return loadOIDs(f)
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

// Recipe describes how to "cook" the data
type Recipe struct {
	Rename string // new name to give data (if set)
	Orig   bool   // send original data as well if set
	Rate   bool   // calculate rate instead of difference
}

// Recipies is a map of recipies to apply calculations to data
type Recipies map[string]Recipe

type dataPoint struct {
	value interface{}
	when  time.Time
}

func normalize(value interface{}) (uint64, error) {
	switch value.(type) {
	case uint:
		return uint64(value.(uint)), nil
	case int:
		return uint64(value.(int)), nil
	case uint64:
		return uint64(value.(uint64)), nil
	case int64:
		return uint64(value.(int64)), nil
	case uint32:
		return uint64(value.(uint32)), nil
	case int32:
		return uint64(value.(int32)), nil
	case Counter32:
		return uint64(value.(Counter32)), nil
	case Counter64:
		return uint64(value.(Counter64)), nil
	default:
		return 0, errors.Errorf("invalid cooked s type:%T value:%v\n", value, value)
	}
}

// CalcSender will create a sender that optionally "cooks" the data
// It requires OIDTag to be true in the snmp criteria to track state
//
// A example:
//    r := snmp.Recipies{
//	   "ifHCInOctets": {"OCTETS_PER_SECOND", true, true},
//    }
//    sender := snmp.SampleSender(hostname)
//    sender = snmp.StripTags(sender, []string{"oid"})
//    sender = snmp.CalcSender(sender, r)
//    Bulkwalker(profile, criteria, freq, sender, nil, nil) error {
//
func CalcSender(sender Sender, cook Recipies) Sender {
	saved := make(map[string]dataPoint)
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		if recipe, ok := cook[name]; ok {
			oid, ok := tags["oid"]
			if !ok {
				return errors.Errorf("no OID saved for calculation on: %s", name)
			}

			var err error
			if prior, ok := saved[oid]; ok {
				this, err := normalize(value)
				if err != nil {
					return err
				}
				that, err := normalize(prior.value)
				if err != nil {
					return err
				}

				// If the new value is *less* than the prior it was either
				// a counter wrap or a device reset.
				// Because device resets happen, we should assume the lesser
				// value is due to that rather than get a possibly huge spike.
				delta := this
				if this >= that {
					delta -= that
				}

				var aka string
				if len(recipe.Rename) > 0 {
					aka = recipe.Rename
				} else {
					aka = name
				}
				if recipe.Rate {
					since := when.Sub(prior.when).Seconds()
					if since > 0 {
						rate := float64(delta) / since
						err = sender(aka, tags, rate, when)
					}
				} else {
					err = sender(aka, tags, delta, when)
				}
			}

			saved[oid] = dataPoint{value, when}
			if recipe.Orig {
				return sender(name, tags, value, when)
			}
			return err
		}
		return sender(name, tags, value, when)
	}
}

// StripSender will create a sender that strips matching tags
func StripSender(sender Sender, taglist []string) Sender {
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		for _, tag := range taglist {
			delete(tags, tag)
		}
		return sender(name, tags, value, when)
	}
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

// BulkColumns returns a gosnmp.WalkFunc that will process results from a bulkwalk
func BulkColumns(client *gosnmp.GoSNMP, crit Criteria, sender Sender, logger *log.Logger) (gosnmp.WalkFunc, error) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	// set up regexp filters
	filterNames := []*regexp.Regexp{}
	for _, n := range crit.Regexps {
		re, err := regexp.Compile(n)
		if err != nil {
			return nil, err
		}
		filterNames = append(filterNames, re)
	}

	// get interface column names and aliases
	columns := make(map[string]string)
	aliases := make(map[string]string)
	suffixValue := func(oid string, lookup map[string]string) error {
		fn := func(pdu gosnmp.SnmpPDU) error {
			switch pdu.Type {
			case gosnmp.OctetString:
				lookup[pdu.Name[len(oid)+1:]] = string(pdu.Value.([]byte))
			default:
				logger.Printf("unknown type: %x value: %v\n", pdu.Type, pdu.Value)
			}
			return nil
		}
		return BulkWalkAll(client, oid, fn)
	}
	if err := suffixValue(ifName, columns); err != nil {
		return nil, err
	}
	if err := suffixValue(ifAlias, aliases); err != nil {
		return nil, err
	}
	for k, v := range crit.Aliases {
		aliases[k] = v
	}

	// our handler that will process each returned SNMP packet
	return func(pdu gosnmp.SnmpPDU) error {
		subOID, v, ok := rtree.Root().LongestPrefix([]byte(pdu.Name))
		if !ok {
			return errors.Errorf("cannot find name for OID: %s", pdu.Name)
		}
		name := v.(string)

		filtered := crit.Keep
		for _, r := range filterNames {
			if r.MatchString(name) {
				if crit.Keep {
					filtered = false
					break
				}
				logger.Printf("omitting name: %s (%s)\n", name, subOID)
				return nil
			}
		}
		if filtered {
			logger.Printf("not keeping name: %s (%s)\n", name, subOID)
			return nil
		}

		var column, alias string
		suffix := pdu.Name[len(subOID)+1:]
		group := oidStrings(suffix)

		// interface names/aliases only apply to OIDs starting with 'if'
		if strings.HasPrefix(name, "if") {
			column = columns[suffix]
			alias = aliases[suffix]
		}
		if len(group) == 0 && len(column) == 0 && suffix != "0" {
			column = makeString(strings.Split(suffix, "."))
		}

		t := map[string]string{}
		if len(column) > 0 {
			t["column"] = column
		}
		if len(alias) > 0 {
			t["alias"] = alias
		}
		if len(group) > 0 && len(group[0]) > 0 {
			t["grouping"] = group[0]
		}
		if len(group) > 1 && len(group[1]) > 0 {
			t["member"] = group[1]
		}
		if len(group) > 3 && len(group[1]) > 0 {
			t["element"] = group[2]
		}

		for k, v := range crit.Tags {
			t[k] = v
		}
		if crit.OIDTag {
			t["oid"] = pdu.Name
		}

		switch pdu.Type {
		case gosnmp.Integer, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		case gosnmp.Counter32:
			switch pdu.Value.(type) {
			case uint32:
				pdu.Value = Counter32(pdu.Value.(uint32))
			case int32:
				pdu.Value = Counter32(pdu.Value.(int32))
			case uint:
				pdu.Value = Counter32(pdu.Value.(uint))
			case int:
				pdu.Value = Counter32(pdu.Value.(int))
			default:
				return errors.Errorf("invalid counter32 name:%s type:%T value:%v\n", name, pdu.Value, pdu.Value)
			}
		case gosnmp.Counter64:
			switch pdu.Value.(type) {
			case uint:
				pdu.Value = Counter64(pdu.Value.(uint))
			case int:
				pdu.Value = Counter64(pdu.Value.(int))
			case uint64:
				pdu.Value = Counter64(pdu.Value.(uint64))
			case int64:
				pdu.Value = Counter64(pdu.Value.(int64))
			case uint32:
				pdu.Value = Counter64(pdu.Value.(uint32))
			case int32:
				pdu.Value = Counter64(pdu.Value.(int32))
			default:
				return errors.Errorf("invalid counter64 name:%s type:%T value:%v\n", name, pdu.Value, pdu.Value)
			}
		case gosnmp.IPAddress:
		case gosnmp.OctetString:
			// sometimes numbers are encoded as strings
			pdu.Value, _ = numerical(string(pdu.Value.([]uint8)))
		default:
			return errors.Errorf("%s - unsupported type: %x value: %v\n", name, pdu.Type, pdu.Value)
		}
		return sender(name, t, pdu.Value, time.Now())
	}, nil
}

// getOID will return the OID representing name
func getOID(oid string) (string, error) {
	if strings.HasPrefix(oid, ".") {
		oid = oid[1:]
	}
	if strings.HasPrefix(oid, "1.") {
		return oid, nil
	}
	fixed, ok := lookupOID[oid]
	if !ok {
		return oid, fmt.Errorf("no OID found for %s", oid)
	}
	return fixed, nil
}

// BulkWalkAll applies bulk walk results to fn once all values returned (synchronously)
func BulkWalkAll(client *gosnmp.GoSNMP, oid string, fn gosnmp.WalkFunc) error {
	pdus, err := client.BulkWalkAll(oid)
	if err != nil {
		return err
	}
	for _, pdu := range pdus {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

// SampleSender returns a Sender that will print out data sent to it
func SampleSender(host string) Sender {
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		if tags != nil && len(tags) > 0 {
			t := make([]string, 0, len(tags))
			for k, v := range tags {
				t = append(t, fmt.Sprintf("%s=%v", k, v))
			}
			fmt.Printf("Host:%s Name:%s Value:%v (%T) Tags:%s\n", host, name, value, value, strings.Join(t, ","))
		} else {
			fmt.Printf("Host:%s Name:%s Value:%v (%T)\n", host, name, value, value)
		}
		return nil
	}
}

// Sampler will do a bulkwalk on the device specified using the given Profile
func Sampler(p Profile, crit Criteria, sender Sender) error {
	client, err := NewClient(p)
	if err != nil {
		return err
	}
	crit.OID, err = getOID(crit.OID)
	if err != nil {
		return err
	}
	if sender == nil {
		sender = SampleSender(client.Target)
	}
	walker, err := BulkColumns(client, crit, sender, nil)
	if err != nil {
		return err
	}
	return BulkWalkAll(client, crit.OID, walker)
}

// Bulkwalker will do a bulkwalk on the device specified in the Profile
func Bulkwalker(p Profile, crit Criteria, freq int, sender Sender, errFn ErrFunc, logger *log.Logger) error {
	client, err := NewClient(p)
	if err != nil {
		return err
	}
	crit.OID, err = getOID(crit.OID)
	if err != nil {
		return err
	}
	if crit.Tags == nil {
		crit.Tags = make(map[string]string)
	}
	crit.Tags["host"] = client.Target
	if debugLogger != nil {
		client.Logger = debugLogger
	}
	walker, err := BulkColumns(client, crit, sender, logger)
	if err != nil {
		return err
	}
	go Poller(client, crit.OID, freq, walker, errFn)
	return nil
}

// Poller will make snmp requests indefinitely
func Poller(client *gosnmp.GoSNMP, oid string, freq int, walker gosnmp.WalkFunc, errFn ErrFunc) {

	c := time.Tick(time.Duration(freq) * time.Second)

	for {
		err := client.BulkWalk(oid, walker)
		if errFn != nil {
			errFn(err)
		}
		select {
		case _ = <-c:
			continue
		case _ = <-done:
			client.Conn.Close()
			return
		}
	}
}

// Quit will exit all active Pollers
func Quit() {
	close(done)
}

// DebugLogger will log all SNMP debug data to the given logger
func DebugLogger(logger *log.Logger) {
	debugLogger = logger
}
