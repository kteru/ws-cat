package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"

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

		LineBuffered bool `long:"line-buffered" description:"Send messages line by line"`

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

		LineBuffered: false,

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

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}()

	fnRead := func() error {
		_, err := io.Copy(os.Stdout, conn)
		if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
			return nil
		}
		return err
	}

	fnWrite := func() error {
		_, err := io.Copy(conn, os.Stdin)
		return err
	}

	fnWriteLineByLine := func() error {
		brd := bufio.NewReader(os.Stdin)
		for {
			bs, err := brd.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					if len(bs) > 0 {
						return conn.WriteMessage(typ, bs)
					}
					return nil
				}
				return err
			}

			if err := conn.WriteMessage(typ, bs); err != nil {
				return err
			}
		}
	}

	errCh := make(chan error, 1)

	// Read
	go func() {
		errCh <- fnRead()
	}()

	// Write
	go func() {
		fn := fnWrite
		if opts.LineBuffered {
			fn = fnWriteLineByLine
		}

		if err := fn(); err != nil {
			errCh <- err
			return
		}

		errCh <- conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}()

	return <-errCh
}
