package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/jessevdk/go-flags"
	"github.com/smith-30/websocket"
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func realMain() error {
	opts := struct {
		Headers     []string `short:"H" long:"header" description:"Add header from <key:value> (Repeat to set multiple)"`
		Origin      string   `short:"o" long:"origin" description:"Set origin"`
		UserPass    string   `short:"u" long:"user" description:"Add header for basic authentication from <username:password>"`
		InsecureTLS bool     `short:"k" long:"insecure" description:"Disable verifing server certificates"`
		CACert      string   `long:"cacert" description:"Set CA"`
		Cert        string   `long:"cert" description:"Set a client certificate"`
		Key         string   `long:"key" description:"Set a client certificate's key"`

		Text   bool `long:"text" description:"Use text frame when sending instead of binary"`
		NoComp bool `long:"no-comp" description:"Disable compression"`
		NoCtx  bool `long:"no-ctx" description:"Disable context takeover"`

		URL string
	}{
		Headers:     []string{},
		Origin:      "",
		UserPass:    "",
		InsecureTLS: false,
		CACert:      "",
		Cert:        "",
		Key:         "",

		Text:   false,
		NoComp: false,
		NoCtx:  false,

		URL: "",
	}

	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	parser.Usage = "[OPTIONS] URL"
	args, err := parser.ParseArgs(os.Args[1:])
	if err != nil {
		parser.WriteHelp(os.Stderr)
		os.Exit(1)
	}
	if len(args) != 1 {
		parser.WriteHelp(os.Stderr)
		os.Exit(1)
	}

	opts.URL = args[0]

	uURL, err := url.ParseRequestURI(opts.URL)
	if err != nil {
		return err
	}

	//
	// Headers
	//

	httpHeader := http.Header{}

	if opts.Origin != "" {
		uOrigin, err := url.ParseRequestURI(opts.Origin)
		if err != nil {
			return err
		}
		httpHeader.Set("Origin", uOrigin.String())
	}

	if opts.UserPass != "" {
		httpHeader.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(opts.UserPass)))
	}

	httpHeaderRegexp := regexp.MustCompile(`^([\w-]+):\s*(.+)`)
	for _, header := range opts.Headers {
		ms := httpHeaderRegexp.FindStringSubmatch(header)
		if len(ms) != 3 {
			parser.WriteHelp(os.Stderr)
			os.Exit(1)
		}
		httpHeader.Set(ms[1], ms[2])
	}

	//
	// TLS
	//

	tlsCfg := &tls.Config{
		ServerName:         uURL.Hostname(),
		InsecureSkipVerify: opts.InsecureTLS,
	}

	if opts.CACert != "" {
		caPEM, err := ioutil.ReadFile(opts.CACert)
		if err != nil {
			return err
		}

		rootCAs := x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
			return fmt.Errorf("Failed to add certs")
		}

		tlsCfg.RootCAs = rootCAs
	}

	if opts.Cert != "" || opts.Key != "" {
		clientCert, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
		if err != nil {
			return err
		}

		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}

	//
	// Go
	//

	dialer := websocket.DefaultDialer
	dialer.TLSClientConfig = tlsCfg

	dialer.EnableCompression = !opts.NoComp
	dialer.AllowClientContextTakeover = !opts.NoCtx

	c, _, err := dialer.Dial(uURL.String(), httpHeader)
	if err != nil {
		return err
	}
	defer c.Close()

	typ := websocket.BinaryMessage
	if opts.Text {
		typ = websocket.TextMessage
	}
	conn := NewReadWriterConn(c, typ)

	errCh := make(chan error, 1)

	// Write
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		errCh <- err
	}()

	// Read
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		errCh <- err
	}()

	if err := <-errCh; err != nil {
		return err
	}

	return nil
}
