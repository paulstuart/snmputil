// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package snmputil

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testOID  = "ifEntry"
	testFreq = 30
)

var (
	testCrit = Criteria{
		OID:  testOID,
		Tags: testTags,
		Freq: testFreq,
	}
)

func walkTest(t *testing.T, p Profile, c Criteria) {
	errFn := func(err error) {
		if err != nil {
			t.Error(err)
		}
	}
	testSender := func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		t.Logf("Name:%s Value:%v Time:%s Tags:%v\n", name, value, ts.Start, tags)
		return nil
	}
	if err := Bulkwalker(p, c, testSender, errFn, logger); err != nil {
		t.Error(err)
	}
}

func TestSNMPv2(t *testing.T) {
	walkTest(t, profileV2, testCrit)
}

func TestSNMPv3(t *testing.T) {
	walkTest(t, profileV3, testCrit)
}

func TestFilters(t *testing.T) {
	errFn := func(err error) {
		if err != nil {
			t.Error(err)
		}
	}
	testSender := func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		t.Logf("Name:%s Value:%v Time:%s Tags:%v\n", name, value, ts.Start, tags)
		if strings.HasSuffix(name, "Time") {
			return fmt.Errorf("did not expect name with Time suffix: %s", name)
		}
		return nil
	}
	crit := Criteria{
		OID:  "system",
		Tags: testTags,
	}
	//crit.Regexps = []string{".*Time"}
	regexps := []string{".*Time"}
	testSender, _ = RegexpSender(testSender, regexps, false)
	if err := Bulkwalker(profileV2, crit, testSender, errFn, nil); err != nil {
		t.Error(err)
	}
	time.Sleep(10 * time.Second)
}

func TestSample(t *testing.T) {
	crit := Criteria{
		OID:  "system",
		Tags: testTags,
	}
	sender := func(name string, tags map[string]string, value interface{}, ts TimeStamp) error {
		t.Logf("Host:%s Name:%s Value:%v Tags:%v\n", tags["host"], name, value, tags)
		return nil
	}
	//Regexps: []string{".*Time"},
	if err := Sampler(profileV3, crit, sender); err != nil {
		t.Error(err)
	}
}

func TestClose(t *testing.T) {
	// give it a chance to respond with values
	time.Sleep(5 * time.Second)
	Quit()
}
