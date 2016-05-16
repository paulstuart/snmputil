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
	debugLogger *log.Logger

	// done will terminate all polling processes if closed
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

// Sender will send the interpreted PDU value to be saved or whathaveyou
type Sender func(string, map[string]string, interface{}, time.Time) error

// Criteria specifies what to query and what to keep
type Criteria struct {
	OID     string            // OID can be dotted string or symbolic name
	Index   string            // OID of table index
	Tags    map[string]string // any additional tags to associate
	Aliases map[string]string // optional column aliases
	Regexps []string          // list of regular expressions to filter by name
	Keep    bool              // Keep matched names if true, discard matches if false
	OIDTag  bool              // add OID as a tag
	Freq    int               // how often to poll for data (in seconds)
	Refresh int               // how often to refresh column data (in seconds)
}

// ErrFunc processes errors and may be nil if desired
type ErrFunc func(error)

// BulkColumns returns a gosnmp.WalkFunc that will process results from a bulkwalk
func BulkColumns(client *gosnmp.GoSNMP, crit Criteria, sender Sender, logger *log.Logger) (gosnmp.WalkFunc, error) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	filter, err := regexpFilter(crit.Regexps, crit.Keep)
	if err != nil {
		return nil, err
	}

	// Interface info
	columns := make(map[string]string)
	aliases := make(map[string]string)
	enabled := make(map[string]bool)
	descriptions := make(map[string]string)

	var index string
	var m sync.Mutex

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
		return BulkWalkAll(client, oid, fn)
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
			if err := BulkWalkAll(client, ifOperStatus, opStatus); err != nil {
				return err
			}
			if err := suffixValue(ifName, columns); err != nil {
				return err
			}
			if err := suffixValue(ifAlias, aliases); err != nil {
				return err
			}
		} else if len(index) > 0 {
			if err := suffixValue(index, descriptions); err != nil {
				return err
			}
		}
		// add manually assigned aliases
		for k, v := range crit.Aliases {
			aliases[k] = v
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
			return nil, err
		}
	}

	if crit.Tags == nil {
		crit.Tags = make(map[string]string)
	}
	crit.Tags["host"] = client.Target

	if err := columnInfo(); err != nil {
		return nil, err
	}

	// because port info can change over a long running process we need
	// to be able to update interface data periodically
	if crit.Refresh > 0 {
		go func() {
			c := time.Tick(time.Duration(crit.Refresh) * time.Second)
			for _ = range c {
				if err := columnInfo(); err != nil {
					logger.Println("refresh error:", err)
				}
			}
		}()
	}

	// our handler that will process each returned SNMP packet
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
		return sender(name, t, value, now)
	}, nil
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

// setup preparse the snmp client and returns a walker function to handle bulkwalks
func setup(p Profile, crit *Criteria, sender Sender, logger *log.Logger) (*gosnmp.GoSNMP, gosnmp.WalkFunc, error) {
	client, err := NewClient(p)
	if err != nil {
		return nil, nil, err
	}
	if crit.OID, err = getOID(crit.OID); err != nil {
		return nil, nil, err
	}
	if len(crit.Index) > 0 {
		if crit.Index, err = getOID(crit.Index); err != nil {
			return nil, nil, err
		}
	}
	if sender == nil {
		sender, _ = DebugSender(nil, nil)
	}
	walker, err := BulkColumns(client, *crit, sender, logger)
	return client, walker, err
}

// Sampler will do a single bulkwalk on the device specified using the given Profile
func Sampler(p Profile, crit Criteria, sender Sender) error {
	client, walker, err := setup(p, &crit, sender, nil)
	if err != nil {
		return err
	}
	return BulkWalkAll(client, crit.OID, walker)
}

// Bulkwalker will do a bulkwalk on the device specified in the Profile
func Bulkwalker(p Profile, crit Criteria, sender Sender, errFn ErrFunc, logger *log.Logger) error {
	client, walker, err := setup(p, &crit, sender, logger)
	if err != nil {
		return err
	}
	if debugLogger != nil {
		client.Logger = debugLogger
	}
	go Poller(client, crit.OID, crit.Freq, walker, errFn)
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
