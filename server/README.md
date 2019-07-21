# Server #
This holds a pretty self-contained server that stores the identities and
nuts in-memory. Using --help shows the options you might need for running
it:

    Usage of ./sqrl_server:
    -cert string
            cert.pem file for TLS
    -h string
            hostname used in creating URLs
    -help string
            print usage
    -key string
            key.pem file for TLS
    -p int
            port to listen on (default 8000)
    -path string
            path used as the root for the SQRL handlers (if not /)

Once running, there's page served from the root that provides the QR code and 
Login buttons.

You can run the server from this directory with:

    go run main.go

or build a binary with:

    go build -o sqrl_server .
