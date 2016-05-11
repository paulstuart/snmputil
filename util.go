// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package snmputil provides helper routines for gosnmp
package snmputil

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

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

// pduType verifies and normalizes the pdu data
func pduType(pdu gosnmp.SnmpPDU) (interface{}, error) {
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
	case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
	case gosnmp.Counter32:
		switch pdu.Value.(type) {
		case uint32:
			return Counter32(pdu.Value.(uint32)), nil
		case int32:
			return Counter32(pdu.Value.(int32)), nil
		case uint:
			return Counter32(pdu.Value.(uint)), nil
		case int:
			return Counter32(pdu.Value.(int)), nil
		default:
			return pdu.Value, errors.Errorf("invalid counter32 type:%T pdu.Value:%v\n", pdu.Value, pdu.Value)
		}
	case gosnmp.Counter64:
		switch pdu.Value.(type) {
		case uint:
			return Counter64(pdu.Value.(uint)), nil
		case int:
			return Counter64(pdu.Value.(int)), nil
		case uint64:
			return Counter64(pdu.Value.(uint64)), nil
		case int64:
			return Counter64(pdu.Value.(int64)), nil
		case uint32:
			return Counter64(pdu.Value.(uint32)), nil
		case int32:
			return Counter64(pdu.Value.(int32)), nil
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
