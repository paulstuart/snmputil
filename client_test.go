// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package snmputil

import (
	"log"
	"os"
	"strconv"
	"testing"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

const (
	sysName = ".1.3.6.1.2.1.1.5.0"
	oidFile = "oids.txt"
)

var (
	// snmpgetnext -v 3 -n "" -u MD5User -a MD5 -A "The Net-SNMP Demo Password" -l authNoPriv test.net-snmp.org sysUpTime
	// snmpget -v 2c -c demopublic test.net-snmp.org SNMPv2-MIB::sysUpTime.0
	// snmpget -v 3 -n "" -u authMD5OnlyUser -a MD5 -A "testingpass0123456789" -l authNoPriv 127.0.0.1 sysUpTime.0

	testPassword  = "testingpass0123456789"
	testHost      = "127.0.0.1"
	testCommunity = "public"
	testUser      = "authMD5OnlyUser"
	testTimeout   = 5
	testRetries   = 1

	profileV2 Profile
	profileV3 Profile
	testTags  = map[string]string{
		"testing": "this is a test",
	}
	logger *log.Logger
)

func envStr(name string, value *string) {
	if env := os.Getenv(name); len(env) > 0 && value != nil {
		*value = env
	}
}

func envInt(name string, value *int) {
	if env := os.Getenv(name); len(env) > 0 && value != nil {
		v, err := strconv.Atoi(env)
		if err != nil {
			panic(err)
		}
		*value = v
	}
}

func init() {
	if err := LoadOIDFile(oidFile); err != nil {
		panic(err)
	}
	if testing.Verbose() {
		logger = log.New(os.Stderr, "", 0)
	}

	envStr("SNMP_HOST", &testHost)
	envStr("SNMP_COMMUNITY", &testCommunity)
	envStr("SNMP_USER", &testUser)
	envStr("SNMP_PASSWORD", &testPassword)
	envInt("SNMP_TIMEOUT", &testTimeout)
	envInt("SNMP_RETRIES", &testRetries)

	profileV2 = Profile{
		Host:      testHost,
		Version:   "2c",
		Community: testCommunity,
		Retries:   testRetries,
		Timeout:   testTimeout,
	}

	profileV3 = Profile{
		Host:      testHost,
		Version:   "3",
		SecLevel:  "AuthNoPriv",
		AuthUser:  testUser,
		AuthProto: "MD5",
		AuthPass:  testPassword,
		Retries:   testRetries,
		Timeout:   testTimeout,
	}
}

func testSysName(client *gosnmp.GoSNMP) error {
	oids := []string{sysName}
	packet, err := client.Get(oids)
	if err != nil {
		return errors.Wrap(err, "get failed")
	}
	if len(packet.Variables) < 1 {
		return errors.New("no packets returned for sysName")
	}
	pdu := packet.Variables[0]
	if pdu.Name != sysName {
		return errors.Errorf("pdu OID (%s) does not match that of sysName", pdu.Name)
	}
	if pdu.Value == nil {
		return errors.New("nil value returned for sysName")
	}
	val := string(pdu.Value.([]uint8))
	if len(val) == 0 {
		return errors.New("no value returned for sysName")
	}
	return nil
}

func TestV2Profile(t *testing.T) {
	client, err := NewClient(profileV2)
	if err != nil {
		t.Error(err)
	}
	if err := testSysName(client); err != nil {
		t.Error(err)
	}
	client.Conn.Close()
}

func TestV3Profile(t *testing.T) {
	client, err := NewClient(profileV3)
	if err != nil {
		t.Error(err)
	}
	if err := testSysName(client); err != nil {
		t.Error(err)
	}
	client.Conn.Close()
}
