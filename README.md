snmputil
========
[![GoDoc](https://godoc.org/github.com/paulstuart/snmputil?status.svg)](https://godoc.org/github.com/paulstuart/snmputil)

snmputil is a library focused on managing bulk polling of SNMP devices

It supports:

  * SNMP versions 1, 2, 2c, 3
  * Bulk polling of tabular data
  * Regexp filtering by name of resulting data
  * Auto generating OID name lookup and processing (if net-snmp-utils is installed)
  * Optional processing of counter data (deltas and differentials)

