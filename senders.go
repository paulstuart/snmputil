// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Recipe describes how to "cook" the data
type Recipe struct {
	Rename string // new name to give data (if set)
	Orig   bool   // send original data as well if set
	Rate   bool   // calculate rate instead of difference
}

// Recipies is a map of recipies to apply calculations to data
type Recipies map[string]Recipe

type dataPoint struct {
	value uint64
	when  time.Time
}

// counter datatype
func counter(value interface{}) (uint64, error) {
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
	default:
		return 0, errors.Errorf("invalid cooked data type:%T value:%v\n", value, value)
	}
}

// CalcSender returns a sender that optionally "cooks" the data
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
	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		if recipe, ok := cook[name]; ok {
			oid, ok := tags["oid"]
			if !ok {
				return errors.Errorf("no OID saved for calculation on: %s", name)
			}

			var err error
			this, err := counter(value)
			if err != nil {
				return err
			}

			if prior, ok := saved[oid]; ok {
				// If the new value is *less* than the prior it was either
				// a counter wrap or a device reset.
				// Because device resets happen, we should assume the lesser
				// value is due to that rather than get a possibly huge spike.
				delta := this
				if this >= prior.value {
					delta -= prior.value
				}

				aka := name
				if len(recipe.Rename) > 0 {
					aka = recipe.Rename
				}
				if recipe.Rate {
					since := ts.Stop.Sub(prior.when).Seconds()
					if since > 0 {
						rate := float64(delta) / since
						err = sender(aka, tags, rate, ts)
					}
				} else {
					err = sender(aka, tags, delta, ts)
				}
			}

			saved[oid] = dataPoint{this, ts.Stop}
			if recipe.Orig {
				return sender(name, tags, value, ts)
			}
			return err
		}
		return sender(name, tags, value, ts)
	}
}

// StripSender returns a sender that strips matching tags
func StripSender(sender Sender, taglist []string) Sender {
	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		for _, tag := range taglist {
			delete(tags, tag)
		}
		return sender(name, tags, value, ts)
	}
}

// IntegerSender returns a sender that makes unsigned counters signed integers
func IntegerSender(sender Sender) Sender {
	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		switch value.(type) {
		case uint:
			value = int(value.(uint))
		case uint32:
			value = int64(value.(uint32))
		case uint64:
			value = int64(value.(uint64))
		}
		return sender(name, tags, value, ts)
	}
}

// RegexpSender returns a Sender that filters results based on name
func RegexpSender(sender Sender, regexps []string, keep bool) (Sender, error) {
	filter, err := regexpFilter(regexps, keep)
	if err != nil {
		return nil, err
	}

	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		if filter(name) {
			return nil
		}

		return sender(name, tags, value, ts)
	}, nil
}

// DebugSender returns a Sender that prints out data sent to it
func DebugSender(sender Sender, logger *log.Logger) (Sender, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "", 0)
	}
	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		host := tags["host"]
		since := ts.Stop.Sub(ts.Start)
		if tags != nil && len(tags) > 0 {
			t := make([]string, 0, len(tags))
			for k, v := range tags {
				if k == "host" {
					continue
				}
				t = append(t, fmt.Sprintf("%s=%v", k, v))
			}
			logger.Printf("Host:%s Name:%s Value:%v (%T/%s) Tags:%s\n", host, name, value, value, since, strings.Join(t, ","))
		} else {
			logger.Printf("Host:%s Name:%s Value:%v (%T/%s)\n", host, name, value, value, since)
		}
		if sender != nil {
			return sender(name, tags, value, ts)
		}
		return nil
	}, nil
}

// SplitSender returns a Sender that sends data to two senders
func SplitSender(s1, s2 Sender) (Sender, error) {
	if s1 == nil || s2 == nil {
		return nil, errors.Errorf("sender cannot be nil")
	}
	return func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		err1 := s1(name, tags, value, ts)
		err2 := s2(name, tags, value, ts)
		if err1 != nil && err2 != nil {
			return errors.Wrap(err1, err2.Error())
		}
		if err1 != nil {
			return err1
		}
		return err2
	}, nil
}
