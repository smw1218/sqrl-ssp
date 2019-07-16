

# sqrl-ssp #
SQRL is a identiy managment system that is meant to replace usernames and passwords for online
account authentication. It requires a user to have a SQRL client that securely manages their 
identity. The server interacts with the SQRL client to authenticate a user (similar but more 
secure than a username/password challenge). Once a user's identity is established, a session
should be established if the desired behavior is for a user to remain "logged in". This is typically
a session cookie or authentication token.

This implements the public parts of the SQRL authentication server API as specified here: https://www.grc.com/sqrl/sspapi.htm.
This library is meant to be pluggable into a broader infrastructure to handle whatever type
of session management you desire. It also allows pluggable storage options and scales horizontally.

[![Documentation](https://godoc.org/github.com/smw1218/sqrl-ssp?status.svg)](https://godoc.org/github.com/smw1218/sqrl-ssp)
[![Go Report Card](https://goreportcard.com/badge/github.com/smw1218/sqrl-ssp)](https://goreportcard.com/report/github.com/smw1218/sqrl-ssp)
