// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Counter32 is 32 bit SNMP counter
type Counter32 uint32

// Counter64 is 32 bit SNMP counter
type Counter64 uint64

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

// normalize counter datatype
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
		return 0, errors.Errorf("invalid cooked data type:%T value:%v\n", value, value)
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
			this, err := normalize(value)
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
					since := when.Sub(prior.when).Seconds()
					if since > 0 {
						rate := float64(delta) / since
						err = sender(aka, tags, rate, when)
					}
				} else {
					err = sender(aka, tags, delta, when)
				}
			}

			saved[oid] = dataPoint{this, when}
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

// NormalSender will create a sender that normalizes datatypes
func NormalSender(sender Sender) Sender {
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		var v interface{}
		switch value.(type) {
		case uint:
			v = int64(value.(uint))
		case int:
			v = int64(value.(int))
		case uint64:
			v = int64(value.(uint64))
		case int64:
			v = int64(value.(int64))
		case uint32:
			v = int64(value.(uint32))
		case int32:
			v = int64(value.(int32))
		case Counter32:
			v = int64(value.(Counter32))
		case Counter64:
			v = int64(value.(Counter64))
		default:
			v = value
		}
		return sender(name, tags, v, when)
	}
}

// RegexpSender returns a Sender that filters results based on name
func RegexpSender(sender Sender, regexps []string, keep bool) (Sender, error) {
	filterNames := []*regexp.Regexp{}
	for _, n := range regexps {
		re, err := regexp.Compile(n)
		if err != nil {
			return nil, errors.Wrapf(err, "pattern: %s", n)
		}
		filterNames = append(filterNames, re)
	}

	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		filtered := keep
		for _, r := range filterNames {
			if r.MatchString(name) {
				if keep {
					filtered = false
					break
				}
				return nil
			}
		}
		if filtered {
			return nil
		}

		return sender(name, tags, value, when)
	}, nil
}

// DebugSender returns a Sender that will print out data sent to it
func DebugSender(sender Sender, logger *log.Logger) (Sender, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "", 0)
	}
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		host := tags["host"]
		if tags != nil && len(tags) > 0 {
			t := make([]string, 0, len(tags))
			for k, v := range tags {
				if k == "host" {
					continue
				}
				t = append(t, fmt.Sprintf("%s=%v", k, v))
			}
			logger.Printf("Host:%s Name:%s Value:%v (%T) Tags:%s\n", host, name, value, value, strings.Join(t, ","))
		} else {
			logger.Printf("Host:%s Name:%s Value:%v (%T)\n", host, name, value, value)
		}
		if sender != nil {
			return sender(name, tags, value, when)
		}
		return nil
	}, nil
}

// SplitSender returns a Sender that will send data to both senders
func SplitSender(s1, s2 Sender) (Sender, error) {
	if s1 == nil || s2 == nil {
		return nil, errors.Errorf("sender cannot be nil")
	}
	return func(name string, tags map[string]string, value interface{}, when time.Time) error {
		err1 := s1(name, tags, value, when)
		err2 := s2(name, tags, value, when)
		if err1 != nil && err2 != nil {
			return errors.Wrap(err1, err2.Error())
		}
		if err1 != nil {
			return err1
		}
		return err2
	}, nil
}
