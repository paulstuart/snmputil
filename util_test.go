package snmputil

import (
	//	"fmt"
	"testing"
	"time"
)

const (
	testOID = "ifEntry"
)

var (
	testCrit = Criteria{
		OID:  testOID,
		Tags: testTags,
	}
	status = make(chan StatsChan)
)

func walkTest(t *testing.T, p Profile) {
	errFn := func(err error) {
		t.Error(err)
	}
	testSender := func(name string, tags map[string]string, value interface{}, when time.Time) error {
		t.Logf("Name:%s Value:%v Time:%s Tags:%v\n", name, value, when, tags)
		return nil
	}
	if err := Bulkwalker(p, testCrit, testSender, 30, errFn, status); err != nil {
		t.Error(err)
	}
}

func TestSNMPv2(t *testing.T) {
	walkTest(t, profileV2)
}

func TestSNMPv3(t *testing.T) {
	walkTest(t, profileV3)
}

func TestFilters(t *testing.T) {
	errFn := func(err error) {
		t.Error(err)
	}
	testSender := func(name string, tags map[string]string, value interface{}, when time.Time) error {
		t.Logf("Name:%s Value:%v Time:%s Tags:%v\n", name, value, when, tags)
		return nil
	}
	crit := Criteria{
		OID:  "system",
		Tags: testTags,
	}
	crit.Regexps = []string{".*Time"}
	if err := Bulkwalker(profileV2, crit, testSender, 30, errFn, status); err != nil {
		t.Error(err)
	}
	time.Sleep(33 * time.Second)
}

func TestSample(t *testing.T) {
	crit := Criteria{
		OID:     "system",
		Tags:    testTags,
		Regexps: []string{".*Time"},
	}
	if err := Sampler(profileV3, crit, nil); err != nil {
		t.Error(err)
	}
}

func TestClose(t *testing.T) {
	// give it a chance to respond with values
	time.Sleep(5 * time.Second)
}
