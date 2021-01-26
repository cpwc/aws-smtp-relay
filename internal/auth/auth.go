/*
Package auth provides an IP and user credentials based authentication handler.
*/
package auth

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"hash"
	"net"
)

// Authentication implements the AuthHandler interface.
type Authentication struct {
	ips  map[string]bool
	user string
	pass []byte
	err  error
}

func validMAC(fn func() hash.Hash, message, messageMAC, key []byte) bool {
	mac := hmac.New(fn, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// Handler validates remote IPs and user credentials.
func (a Authentication) Handler(
	remoteAddr net.Addr,
	mechanism string,
	username []byte,
	password []byte,
	shared []byte,
) (bool, error) {
	if a.err != nil {
		return false, a.err
	}
	if a.ips != nil {
		ip := remoteAddr.(*net.TCPAddr).IP.String()
		if a.ips[ip] != true {
			return false, errors.New("Invalid client IP: " + ip)
		}
	}
	if a.user != "" {
		if string(username) != a.user {
			return false, errors.New("Invalid username: " + string(username))
		}
		if mechanism == "CRAM-MD5" {
			messageMac := make([]byte, hex.DecodedLen(len(password)))
			n, err := hex.Decode(messageMac, password)
			if err != nil {
				return false, err
			}
			return validMAC(md5.New, shared, messageMac[:n], a.pass), nil
		}
	}
	return true, nil
}

// New creates a new Authentication config.
// ips are required for IP access restriction.
// user is required for LOGIN, PLAIN and CRAM-MD5 authentication.
// pass is required for CRAM-MD5 authentication (requires plain text password).
func New(
	ips map[string]bool,
	user string,
	pass []byte,
) Authentication {
	var err error
	return Authentication{
		ips:  ips,
		user: user,
		pass: pass,
		err:  err,
	}
}
