// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

type pduReader func(gosnmp.SnmpPDU) (interface{}, error)

// makeString converts ascii octets into a string
func makeString(bits []string) string {
	chars := make([]byte, len(bits))
	for i, bit := range bits {
		n, _ := strconv.Atoi(bit)
		chars[i] = byte(n)
	}
	return cleanString(chars)
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
		words = append(words, makeString(bits[i+1:end]))
		i += cnt
	}
	return words
}

// cleanString creates a printable string
func cleanString(in []byte) string {
	r := bytes.Runes(in)
	acc := make([]rune, 0, len(r))
	for _, c := range r {
		if strconv.IsPrint(c) {
			acc = append(acc, c)
		}
	}
	return string(acc)
}

// dateTime will convert snmp datetime octets into time.Time
func dateTime(pdu gosnmp.SnmpPDU) (interface{}, error) {
	d := pdu.Value.([]byte)
	offset := 0
	switch len(d) {
	case 8:
	case 11:
		offset = (int(d[9]) * 3600) + (int(d[10]) * 60)
		if string(d[8]) == "-" {
			offset = -offset
		}
	default:
		return time.Time{}, errors.Errorf("invalid octet length:%d", len(d))
	}
	year := int(d[0])<<8 + int(d[1])
	month := time.Month(d[2])
	nano := int(d[7]) * 1024
	loc := time.FixedZone("UTC", offset)
	return time.Date(year, month, int(d[3]), int(d[4]), int(d[5]), int(d[6]), nano, loc), nil
}

// pduType verifies and normalizes the pdu data
func pduType(pdu gosnmp.SnmpPDU) (interface{}, error) {
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
	case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
	case gosnmp.Counter32:
		switch pdu.Value.(type) {
		case uint32:
			return uint32(pdu.Value.(uint32)), nil
		case int32:
			return uint32(pdu.Value.(int32)), nil
		case uint:
			return uint32(pdu.Value.(uint)), nil
		case int:
			return uint32(pdu.Value.(int)), nil
		default:
			return pdu.Value, errors.Errorf("invalid counter32 type:%T pdu.Value:%v\n", pdu.Value, pdu.Value)
		}
	case gosnmp.Counter64:
		switch pdu.Value.(type) {
		case uint:
			return uint64(pdu.Value.(uint)), nil
		case int:
			return uint64(pdu.Value.(int)), nil
		case uint64:
			return uint64(pdu.Value.(uint64)), nil
		case int64:
			return uint64(pdu.Value.(int64)), nil
		case uint32:
			return uint64(pdu.Value.(uint32)), nil
		case int32:
			return uint64(pdu.Value.(int32)), nil
		default:
			return pdu.Value, errors.Errorf("invalid counter64 type:%T pdu.Value:%v\n", pdu.Value, pdu.Value)
		}
	case gosnmp.OctetString:
		s := cleanString([]byte(pdu.Value.([]uint8)))

		// sometimes numbers are encoded as strings
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f, nil
		}
		if i, err := strconv.ParseInt(s, 0, 64); err == nil {
			return i, nil
		}
		return s, nil
	default:
		return pdu.Value, errors.Errorf("unsupported type: %x (%T), pdu.Value: %v\n", pdu.Type, pdu.Value, pdu.Value)
	}
	return pdu.Value, nil
}

// getOID will return the OID representing name
func getOID(oid string) (string, error) {
	if strings.HasPrefix(oid, ".") {
		return oid, nil
	}
	fixed, ok := lookupOID[oid]
	if !ok {
		return oid, errors.Errorf("no OID found for %s", oid)
	}
	return fixed, nil
}

// regexpFilter returns a function that filters results based on name
// returns true if name is not valid
func regexpFilter(regexps []string, keep bool) (func(string) bool, error) {
	if len(regexps) == 0 {
		return func(name string) bool {
			return false
		}, nil
	}
	filterNames := []*regexp.Regexp{}
	for _, n := range regexps {
		re, err := regexp.Compile(n)
		if err != nil {
			return nil, errors.Wrapf(err, "pattern: %s", n)
		}
		filterNames = append(filterNames, re)
	}

	return func(name string) bool {
		for _, r := range filterNames {
			if r.MatchString(name) {
				return !keep
			}
		}
		return keep
	}, nil
}
