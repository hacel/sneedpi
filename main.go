package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/babolivier/go-doh-client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/spf13/pflag"
)

var resolver *doh.Resolver

func transfer(to io.WriteCloser, from io.ReadCloser) {
	defer to.Close()
	defer from.Close()
	io.Copy(to, from)
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	logger := log.With().Str("hostname", r.URL.Hostname()).Logger()
	addr := r.URL.Hostname()
	if resolver != nil {
		// Host look up over DoH
		a, _, err := resolver.LookupA(r.URL.Hostname())
		if err != nil {
			logger.Error().Err(err).Msg("")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		addr = a[0].IP4
	}
	// Dial remote
	port := "443"
	if r.URL.Port() != "" {
		port = r.URL.Port()
	}
	addr = addr + ":" + port
	logger = logger.With().Str("address", addr).Logger()
	logger.Info().Msg("dialing...")
	remote_conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		logger.Error().Err(err).Msg("dial error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	logger.Info().Msg("connected")
	// Hijack client conn
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error().Msg("hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		logger.Error().Err(err).Msg("")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Read client hello
	buf := make([]byte, 1024)
	n, err := client_conn.Read(buf)
	if err != nil {
		logger.Error().Err(err).Msg("")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf = buf[:n]
	// Split packet on TLS server name indicator
	sni := []byte(r.URL.Hostname())
	sniIdx := bytes.Index(buf, sni)
	if sniIdx == -1 {
		logger.Error().Msg("could not find SNI in client request")
		http.Error(w, "Could not find SNI in client request", http.StatusInternalServerError)
		return
	}
	splitSniIdx := sniIdx + len(sni)/2
	if _, err = remote_conn.Write(buf[:splitSniIdx]); err != nil {
		logger.Error().Err(err).Msg("")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err = remote_conn.Write(buf[splitSniIdx:]); err != nil {
		logger.Error().Err(err).Msg("")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Proxy the rest of the connection
	go transfer(remote_conn, client_conn)
	go transfer(client_conn, remote_conn)
}

func main() {
	ip := pflag.String("ip", "127.0.0.1", "IP")
	port := pflag.String("port", "8080", "Port")
	dns := pflag.String("dns", "", "DoH compatible DNS server")
	pflag.Parse()

	// Setup logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if *dns != "" {
		// Setup DoH resolver
		resolver = &doh.Resolver{
			Host:  *dns,
			Class: doh.IN,
		}
	}

	server := &http.Server{
		Addr: *ip + ":" + *port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
				return
			}
			resp, err := http.DefaultTransport.RoundTrip(r)
			if err != nil {
				log.Error().Err(err).Str("hostname", r.URL.Hostname()).Msg("")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Str("ip", *ip).Str("port", *port).Str("dns", *dns).Err(err).Msg("")
		}
	}()
	log.Info().Str("ip", *ip).Str("port", *port).Str("dns", *dns).Msg("Running")

	<-ctx.Done()
	stop()
	server.Close()
	wg.Wait()
	log.Info().Msg("Stopped")
}
