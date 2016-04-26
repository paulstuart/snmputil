package snmputil

import (
	"fmt"
	"testing"

	"github.com/soniah/gosnmp"
)

const (
	sysName = ".1.3.6.1.2.1.1.5.0"
	oidFile = "oids.txt"
	//testOID       = "ifEntry"
	testHost      = "test.net-snmp.org"
	testCommunity = "demopublic"
	testPassword  = "The Net-SNMP Demo Password"
)

var (
	//snmpgetnext -v 3 -n "" -u MD5User -a MD5 -A "The Net-SNMP Demo Password" -l authNoPriv test.net-snmp.org sysUpTime
	//snmpget -v 2c -c demopublic test.net-snmp.org SNMPv2-MIB::sysUpTime.0

	profileV2 = Profile{
		Host:      testHost,
		Version:   "2c",
		Community: testCommunity,
		Retries:   1,
		Timeout:   60,
	}

	profileV3 = Profile{
		Host:      testHost,
		Version:   "3",
		SecLevel:  "AuthNoPriv",
		AuthUser:  "MD5User",
		AuthProto: "MD5",
		AuthPass:  testPassword,
		Retries:   1,
		Timeout:   60,
	}

	testTags = map[string]string{
		"testing": "this is a test",
	}
)

func init() {
	if err := LoadOIDFile(oidFile); err != nil {
		panic(err)
	}
	Verbose = testing.Verbose()
}

func testSysName(client *gosnmp.GoSNMP) error {
	oids := []string{sysName}
	packet, err := client.Get(oids)
	if err != nil {
		return err
	}
	if len(packet.Variables) < 1 {
		return fmt.Errorf("no packets returned for sysName")
	}
	pdu := packet.Variables[0]
	if pdu.Name != sysName {
		return fmt.Errorf("pdu OID (%s) does not match that of sysName", pdu.Name)
	}
	if pdu.Value == nil {
		return fmt.Errorf("nil value returned for sysName")
	}
	val := string(pdu.Value.([]uint8))
	if len(val) == 0 {
		return fmt.Errorf("no value returned for sysName")
	}
	return nil
}

/*
func walkTest(t *testing.T, p Profile) {
	testSender := func(name string, tags map[string]string, values map[string]interface{}, when time.Time) error {
		t.Logf("Name: %s Time: %s\n", name, when)
		for k, v := range tags {
			t.Logf("Tag name: %s value: %s\n", k, v)
		}
		for k, v := range values {
			t.Logf("Value name: %s value: %v\n", k, v)
		}
		return nil
	}
	//Debug = true
	if err := Bulkster(p, testOID, testTags, testSender, 1, 0); err != nil {
		t.Error(err)
	}
	// give it a chance to respond with values
	time.Sleep(10 * time.Second)
}

func TestSNMPv2(t *testing.T) {
	walkTest(t, profileV2)
}

func TestSNMPv3(t *testing.T) {
	walkTest(t, profileV3)
}
*/

func TestV2Profile(t *testing.T) {
	client, err := NewClient(profileV2)
	if err != nil {
		t.Error(err)
	}
	if err := testSysName(client); err != nil {
		t.Error(err)
	}
}

func TestV3Profile(t *testing.T) {
	client, err := NewClient(profileV3)
	if err != nil {
		t.Error(err)
	}
	if err := testSysName(client); err != nil {
		t.Error(err)
	}
}
