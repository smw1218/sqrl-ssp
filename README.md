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

This project is still very much a work in-progress. All the endpoints log a ton of debugging information.

[![Documentation](https://godoc.org/github.com/smw1218/sqrl-ssp?status.svg)](https://godoc.org/github.com/smw1218/sqrl-ssp)
[![Go Report Card](https://goreportcard.com/badge/github.com/smw1218/sqrl-ssp)](https://goreportcard.com/report/github.com/smw1218/sqrl-ssp)

## Integration ##
The ssp.SqrlSspAPI struct is a configurable server that exposes http.HandlerFuncs that implement the SSP API. The main one
is the ssp.SqrlSspAPI.Cli handler which directly handles communication from the SQRL client. These endpoints can be configured to 
run as a standalone service or as part of a larger API structure. There are several required pieces
of configuration that must be provided to integrate SQRL into broader user management. 

### Authenticator ###
The basis of the SSP API is to manage SQRL identities. The goal of this library is to manage these identities and allow
for loosly coupling an identity to a "user". This is similar in concept to a user having a username and password which may be
changed for a given user. A SQRL idenity can be associated with a user, and at a later time that identity may be disabled or
removed from a user, or a new identity may be associated with that user. These actions are supported by the ssp.Authenticator
interface.

### Hoard and AuthStore ##
The SSP API has requirements for storage exposed by the Hoard and AuthStore interfaces. Because an extended pun is always fun, a Hoard stores Nuts.
Nuts are SQRL's cryptographic nonces. A Hoard also has stores pending auth information associated with the Nut. These are ephemperal and have an
expiration so are best stored in a in-memory store like Redis or memcached. The AuthStore saves the SQRL identity information and should be a durable database like PostgreSQL or MariaDB. Both are interfaces so any storage should be able to be plugged in. The ssp package provides map-backed implementations for both which are *NOT* recommended for production use. 

I've written a Redis-backed Hoard implementation at [github.com/smw1218/sqrl-redishoard](https://github.com/smw1218/sqrl-redishoard)
I've written a GORM-backed (GORM supports several different database backends) AuthStore implementation at [github.com/smw1218/sqrl-gormauthstore](https://github.com/smw1218/sqrl-gormauthstore)


### Trees ###
Trees produce Nuts. There are several ways to produce a secure nonce. GRC reccommends an in-memory counter-based nonce, but the design
does not easily scale horizontally. Multiple servers could produce the same nonce if they are not externally coordinated (like through
a globally consistent counter like a PostgreSQL sequence.) The ssp package provides ssp.GrcTree as an implementation of this, but I 
reccommend using ssp.RandomTree if you're using multiple servers.

## API ##
This package only implements the public parts of the SSP API intentionally. The callbacks provided by the Authenticator interface
should allow integration with any auth system; includig embedding in a larger existing auth service or aloowing the SSP service to
stand alone and send requests to another authorization and/or user management service.

I've also made some convenient additions to the standard API.

### /nut.sqrl ###
In addition to the nut, this endpoint returns a "pag" parameter that must be used by the web browser (or other user-agent)
to poll the /pag.sqrl endpoint. For security, it's required to tie the nut to the original requestor so that another
casual observer of the QR code cannot hijack authentication. The GRC server does this implicitly through browser cookies.
The pagnut makes this explicit and is not tied to cookies to make it more friendly to API-only usage. The pag value must 
be kept secret at the user-agent to ensure security.

I've also added an "exp" parameter which is the expiration in seconds of the nut. This may be used to refresh the nut/png
to prevent users from failing to authenticate due to using a stale nut.

I also support a JSON version of the response that can be accessed by adding "Accept: application/json" header to the request.
By default it always returns application/x-www-form-urlencoded as per the GRC spec.

### /png.sqrl ###
Normally, a "nut" parameter which comes from the /nut.sqrl endpoint is required to produce a valid QR code. I've added
some additional functionality to allow this to be one-step. Calling /png.sqrl with no parameters will return a new QR
code with the nut values as headers:

    Sqrl-Nut
    Sqrl-Pag
    Sqrl-Exp

If a user-agent has easy access to the headers of the image request, this is a good way to get everything in one call.
These headers are NOT included if the nut parameter is provided as it is assumed the caller has already gotten them from
the /nut.sqrl endpoint.

### /pag.sqrl ###
This endpoint requires sending both the "nut" and "pag" parameters. See section for /nut.sqrl.
Otherwise it follows the GRC spec and returns a redirect URL that should authorize the user.

I also support a JSON version of the response that can be accessed by adding "Accept: application/json" header to the request.
The response body is an object with a single "url" parameter.
