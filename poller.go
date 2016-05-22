// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	radix "github.com/hashicorp/go-immutable-radix"
	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

var (
	snmpLogger *log.Logger

	// done terminates all polling processes if closed
	done = make(chan struct{})

	// how to break up column indexes with multiple elements
	multiName = strings.Fields("Grouping Member Element Item")
	rtree     = radix.New()
)

const (
	ifName       = ".1.3.6.1.2.1.31.1.1.1.1"
	ifAlias      = ".1.3.6.1.2.1.31.1.1.1.18"
	ifOperStatus = ".1.3.6.1.2.1.2.2.1.8"
)

// TimeStamp tracks execution tim
type TimeStamp struct {
	Start, Stop time.Time
}

// WalkFunc is an import convenince
type WalkFunc gosnmp.WalkFunc

// Sender sends the interpreted PDU value to be saved or whathaveyou
type Sender func(string, map[string]string, interface{}, TimeStamp) error

// Criteria specifies what to query and what to keep
type Criteria struct {
	OID     string            // OID can be dotted string or symbolic name
	Index   string            // OID of table index
	Tags    map[string]string // any additional tags to associate
	Aliases map[string]string // optional column aliases
	Regexps []string          // list of regular expressions to filter by name
	Keep    bool              // Keep matched names if true, discard matches if false
	OIDTag  bool              // add OID as a tag
	Count   int               // how many times to poll for data (0 is forever)
	Freq    int               // how often to poll for data (in seconds)
	Refresh int               // how often to refresh column data (in seconds)
}

// ErrFunc processes errors and may be nil if desired
type ErrFunc func(error)

// ResetFunc resets the time start for SNMP capture
type ResetFunc func()

type avgTime func() int

// bulkColumns returns a gosnmp.WalkFunc that processes results from a bulkwalk
func bulkColumns(client *gosnmp.GoSNMP, crit Criteria, sender Sender, logger *log.Logger) (WalkFunc, avgTime, error) {
	filter, err := regexpFilter(crit.Regexps, crit.Keep)
	if err != nil {
		return nil, nil, err
	}

	// Interface info
	columns := make(map[string]string)
	aliases := make(map[string]string)
	enabled := make(map[string]bool)
	descriptions := make(map[string]string)

	var index string
	var m, tux sync.Mutex
	var timer time.Time
	times := make([]int, 32)
	timeIn := 0
	timeCnt := 0

	started := func(n time.Time) TimeStamp {
		tux.Lock()
		t := timer
		d := int(n.Sub(t).Nanoseconds() / 1000000)
		if timeIn == len(times) {
			timeIn = 0
			times[timeIn] = d
		} else {
			times[timeIn] = d
			timeIn++
			if timeCnt < len(times) {
				timeCnt++
			}
		}
		tux.Unlock()
		return TimeStamp{t, n}
	}

	avg := func() int {
		tux.Lock()
		defer tux.Unlock()
		timer = time.Now()
		if timeCnt == 0 {
			return 0
		}
		total := 0
		for i := 0; i < timeCnt; i++ {
			total += times[i]
		}
		return total / timeCnt
	}
	// get interface column names and aliases
	suffixValue := func(oid string, lookup map[string]string) error {
		fn := func(pdu gosnmp.SnmpPDU) error {
			switch pdu.Type {
			case gosnmp.OctetString:
				lookup[pdu.Name[len(oid)+1:]] = cleanString(pdu.Value.([]byte))
			default:
				return errors.Errorf("unknown type: %x value: %v\n", pdu.Type, pdu.Value)
			}
			return nil
		}
		return bulkWalker(client, oid, fn)
	}

	// check for active interfaces
	opStatus := func(pdu gosnmp.SnmpPDU) error {
		const prefix = len(ifOperStatus) + 1
		if pdu.Type == gosnmp.Integer {
			enabled[pdu.Name[prefix:]] = pdu.Value.(int) == 1
		}
		return nil
	}

	columnInfo := func() error {
		m.Lock()
		defer m.Unlock()

		// mib-2
		if strings.HasPrefix(crit.OID, ".1.3.6.1.2.1") {
			if err := bulkWalker(client, ifOperStatus, opStatus); err != nil {
				return err
			}
			if err := suffixValue(ifName, columns); err != nil {
				return err
			}
			if err := suffixValue(ifAlias, aliases); err != nil {
				return err
			}
			// add manually assigned aliases
			cname := make(map[string]string)
			for k, v := range columns {
				cname[v] = k
			}
			for k, v := range crit.Aliases {
				col, ok := cname[k]
				if !ok {
					return errors.Errorf("host %s does not have interface:%s", client.Target, k)
				}
				aliases[col] = v
			}
		} else if len(index) > 0 {
			if err := suffixValue(index, descriptions); err != nil {
				return err
			}
		}
		return nil
	}

	// apply tags to resulting value
	pduTags := func(name, suffix string) (map[string]string, bool) {
		t := map[string]string{}

		// some oid indexes are comprised of multiple words
		group := oidStrings(suffix)

		// interface names/aliases only apply to OIDs starting with 'if'
		// TODO: there should be a more "formal" way of applying
		if strings.HasPrefix(name, "if") && len(suffix) > 0 {
			m.Lock()
			if _, ok := enabled[suffix]; !ok {
				m.Unlock()
				return nil, false
			}
			if column, ok := columns[suffix]; ok && len(column) > 0 {
				t["column"] = column
			}
			if alias, ok := aliases[suffix]; ok && len(alias) > 0 {
				t["alias"] = alias
			}
			m.Unlock()
		}
		if len(index) > 0 && len(suffix) > 0 {
			m.Lock()
			if desc, ok := descriptions[suffix]; ok && len(desc) > 0 {
				t["descr"] = desc
			}
			m.Unlock()
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
		return t, true
	}

	if len(crit.Index) > 0 {
		if index, err = getOID(crit.Index); err != nil {
			return nil, nil, err
		}
	}

	if crit.Tags == nil {
		crit.Tags = make(map[string]string)
	}
	crit.Tags["host"] = client.Target

	if err := columnInfo(); err != nil {
		return nil, nil, err
	}

	// because port info can change over a long running process we need
	// to be able to update interface data periodically
	if crit.Refresh > 0 {
		go func() {
			c := time.Tick(time.Duration(crit.Refresh) * time.Second)
			for _ = range c {
				if err := columnInfo(); err != nil {
					logger.Println(errors.Wrap(err, "refresh error"))
				}
			}
		}()
	}

	// our handler that handles each returned SNMP packet
	return func(pdu gosnmp.SnmpPDU) error {
		now := time.Now()
		sub, v, ok := rtree.Root().LongestPrefix([]byte(pdu.Name))
		if !ok {
			return errors.Errorf("cannot find name for OID: %s", pdu.Name)
		}
		subOID := string(sub)
		oInfo, ok := oidBase[subOID]
		if !ok {
			return errors.Errorf("cannot find info for OID: %s", subOID)
		}
		name := v.(string)
		if filter(name) {
			return nil
		}

		var suffix string
		if len(subOID) < len(pdu.Name) {
			suffix = pdu.Name[len(subOID)+1:]
		}
		t, ok := pduTags(name, suffix)
		if !ok {
			return nil
		}
		for k, v := range crit.Tags {
			t[k] = v
		}
		if crit.OIDTag {
			t["oid"] = pdu.Name
		}

		value, err := oInfo.Fn(pdu)
		if err != nil {
			logger.Printf("bad bulk name:%s error:%s\n", name, err)
			return nil
		}
		return sender(name, t, value, started(now))
	}, avg, nil
}

// bulkWalker applies bulk walk results to fn once all values returned (synchronously)
func bulkWalker(client *gosnmp.GoSNMP, oid string, fn WalkFunc) error {
	if len(oid) == 0 {
		return errors.Errorf("no OID specified")
	}
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

// setup preparse the snmp client and returns a walker function to handle bulkwalks
func setup(p Profile, crit *Criteria, sender Sender, logger *log.Logger) (string, *gosnmp.GoSNMP, WalkFunc, avgTime, error, *log.Logger) {
	client, err := NewClient(p)
	if err != nil {
		return "", nil, nil, nil, err, logger
	}
	oid, err := getOID(crit.OID)
	if err != nil {
		return oid, nil, nil, nil, err, logger
	}
	if len(crit.Index) > 0 {
		if crit.Index, err = getOID(crit.Index); err != nil {
			return oid, nil, nil, nil, err, logger
		}
	}
	if sender == nil {
		sender, _ = DebugSender(nil, nil)
	}
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	walker, tCtl, err := bulkColumns(client, *crit, sender, logger)
	return oid, client, walker, tCtl, err, logger
}

// Sampler does a single bulkwalk on the device specified using the given Profile
func Sampler(p Profile, c Criteria, s Sender) error {
	oid, client, walker, avg, err, _ := setup(p, &c, s, nil)
	if err != nil {
		return err
	}
	avg()
	return bulkWalker(client, oid, walker)
}

// Walker applies bulk walk results to fn once all values returned (synchronously)
func Walker(p Profile, oid string, fn WalkFunc) error {
	client, err := NewClient(p)
	if err != nil {
		return err
	}
	return bulkWalker(client, oid, fn)
}

// Poller does a bulkwalk on the device specified in the Profile
func Poller(p Profile, c Criteria, s Sender, fn ErrFunc, l *log.Logger) error {
	oid, client, walker, avg, err, l := setup(p, &c, s, l)
	if err != nil {
		return err
	}

	freq := c.Freq
	delay := freq
	_, name, ok := rtree.Root().LongestPrefix([]byte(oid))
	if !ok {
		name = oid
	}

	defer client.Conn.Close()
	clk := time.Tick(time.Duration(delay) * time.Second)
	for {
		// if the last request took longer than the polling frequency
		// then update the polling frequency to accomodate slower responses

		// stats are in ms but we work in seconds
		mean := avg() / 1000
		tick := func(adj int) {
			l.Printf("Adjusting poll for %s/%s from %d to %d seconds (%ds)\n", client.Target, name, delay, adj, mean)
			delay = adj
			clk = time.Tick(time.Duration(delay) * time.Second)
		}
		if mean > delay {
			// adjust to next whole minute
			tick(((mean / 60) + 1) * 60)
			// and pause to sync to new period
			time.Sleep(time.Duration(delay-mean) * time.Second)
		} else if mean < (delay-60) && delay > freq {
			// adjust back down if times improve
			tick(delay - 60)
		}
		err := client.BulkWalk(oid, gosnmp.WalkFunc(walker))
		if err != nil {
			l.Println(errors.Wrap(err, "bulkwalk failed"))
		}

		// errors represent an event occurred, for stats
		if fn != nil {
			fn(err)
		}

		if c.Count > 0 {
			c.Count--
			if c.Count == 0 {
				return err
			}
		}

		select {
		case _ = <-clk:
			continue
		case _ = <-done:
			return nil
		}
	}
}

// OIDCollector returns a walker function that collects OIDs encountered
func OIDCollector(c chan string) WalkFunc {
	return func(pdu gosnmp.SnmpPDU) error {
		c <- pdu.Name
		return nil
	}
}

// Quit exits all active Pollers
func Quit() {
	close(done)
}

// DebugLogger logs all SNMP debug data to the given logger
func DebugLogger(logger *log.Logger) {
	snmpLogger = logger
}
