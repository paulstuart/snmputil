// Copyright 2016 Paul Stuart. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package snmputil

import (
	"time"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

const (
	defaultPort = 161
)

// Profile contains the settings needed to establish an SNMP connection
type Profile struct {
	Host, Community, Version string
	Port, Timeout, Retries   int
	// for SNMP v3
	SecLevel, AuthUser, AuthPass, AuthProto, PrivProto, PrivPass string
}

// newClient returns an snmp client that has connected to an snmp agent
func newClient(p Profile) (*gosnmp.GoSNMP, error) {
	var ok bool
	var aProto gosnmp.SnmpV3AuthProtocol
	var pProto gosnmp.SnmpV3PrivProtocol
	var msgFlags gosnmp.SnmpV3MsgFlags

	authProto := map[string]gosnmp.SnmpV3AuthProtocol{
		"NoAuth": gosnmp.NoAuth,
		"MD5":    gosnmp.MD5,
		"SHA":    gosnmp.SHA,
	}
	privacy := map[string]gosnmp.SnmpV3PrivProtocol{
		"NoPriv": gosnmp.NoPriv,
		"DES":    gosnmp.DES,
		"AES":    gosnmp.AES,
	}

	authCheck := func() error {
		if len(p.AuthPass) < 1 {
			return errors.Errorf("no SNMPv3 password for host %s", p.Host)
		}
		if aProto, ok = authProto[p.AuthProto]; !ok {
			return errors.Errorf("invalid auth protocol %s for host %s", p.AuthProto, p.Host)
		}
		return nil
	}

	v3auth := func() (*gosnmp.UsmSecurityParameters, error) {
		if len(p.AuthUser) < 1 {
			return nil, errors.Errorf("username not found for snmpv3 host %s", p.Host)
		}

		switch p.SecLevel {
		case "NoAuthNoPriv":
			msgFlags = gosnmp.NoAuthNoPriv
			return &gosnmp.UsmSecurityParameters{
				UserName:               p.AuthUser,
				AuthenticationProtocol: gosnmp.NoAuth,
				PrivacyProtocol:        gosnmp.NoPriv,
			}, nil
		case "AuthNoPriv":
			msgFlags = gosnmp.AuthNoPriv
			return &gosnmp.UsmSecurityParameters{
				UserName:                 p.AuthUser,
				AuthenticationProtocol:   aProto,
				AuthenticationPassphrase: p.AuthPass,
				PrivacyProtocol:          gosnmp.NoPriv,
			}, authCheck()
		case "AuthPriv":
			msgFlags = gosnmp.AuthPriv
			if len(p.PrivPass) < 1 {
				return nil, errors.New("missing snmp v3 privacy password")
			}

			if pProto, ok = privacy[p.PrivProto]; !ok {
				return nil, errors.Errorf("invalid in Privcy Protocol %s for host %s", p.PrivProto, p.Host)
			}

			return &gosnmp.UsmSecurityParameters{
				UserName:                 p.AuthUser,
				AuthenticationProtocol:   aProto,
				AuthenticationPassphrase: p.AuthPass,
				PrivacyProtocol:          pProto,
				PrivacyPassphrase:        p.PrivPass,
			}, authCheck()

		default:
			return nil, errors.Errorf("invalid security level %s for host %s", p.SecLevel, p.Host)
		}
	}

	if p.Port == 0 {
		p.Port = defaultPort
	}

	client := &gosnmp.GoSNMP{
		Target:  p.Host,
		Port:    uint16(p.Port),
		Timeout: time.Duration(p.Timeout) * time.Second,
		Retries: p.Retries,
	}

	switch p.Version {
	case "1":
		client.Version = gosnmp.Version1
		client.Community = p.Community
	case "", "2", "2c":
		client.Version = gosnmp.Version2c
		client.Community = p.Community
	case "3":
		usmParams, err := v3auth()
		if err != nil {
			return nil, err
		}
		client.MsgFlags = msgFlags
		client.SecurityModel = gosnmp.UserSecurityModel
		client.SecurityParameters = usmParams
		client.Version = gosnmp.Version3
	default:
		return nil, errors.New("invalid snmp version")
	}

	if snmpLogger != nil {
		client.Logger = snmpLogger
	}

	return client, client.Connect()
}
