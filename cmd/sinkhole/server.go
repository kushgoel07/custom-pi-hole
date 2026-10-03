package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

func serve(ctx context.Context, address string, handler dns.Handler) error {
	// Open both ports before starting the servers.
	udpConn, err := net.ListenPacket("udp", address)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpConn.Close()

	// If address uses port 0, TCP needs the port UDP was given.
	tcpListener, err := net.Listen("tcp", udpConn.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer tcpListener.Close()

	udpServer := &dns.Server{PacketConn: udpConn, Handler: handler, UDPSize: 1232}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	serverErrors := make(chan error, 2)
	started := make(chan struct{}, 2)
	udpServer.NotifyStartedFunc = func() { started <- struct{}{} }
	tcpServer.NotifyStartedFunc = func() { started <- struct{}{} }
	go func() { serverErrors <- udpServer.ActivateAndServe() }()
	go func() { serverErrors <- tcpServer.ActivateAndServe() }()

	// Wait until both servers are ready.
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case err := <-serverErrors:
			return err
		}
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := udpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Printf("UDP shutdown: %v", err)
		}
		if err := tcpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Printf("TCP shutdown: %v", err)
		}
	}()
	log.Printf("DNS listening on %s (UDP/TCP)", udpConn.LocalAddr())

	select {
	case <-ctx.Done():
		return nil
	case err := <-serverErrors:
		return err
	}
}
