package sinkhole

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureWriter struct {
	addr net.Addr
	msg  *dns.Msg
}

func (writer *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
}

func (writer *captureWriter) RemoteAddr() net.Addr {
	return writer.addr
}

func (writer *captureWriter) WriteMsg(message *dns.Msg) error {
	writer.msg = message.Copy()
	return nil
}
func (writer *captureWriter) Write(b []byte) (int, error) {
	return len(b), nil

}
func (writer *captureWriter) Close() error        { return nil }
func (writer *captureWriter) TsigStatus() error   { return nil }
func (writer *captureWriter) TsigTimersOnly(bool) {}
func (writer *captureWriter) Hijack()             {}

func localHandler(upstream string) *Handler {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	return NewHandler(HandlerConfig{
		Blocked:     Domains{"ads.example": {}},
		Allowed:     Domains{"safe.ads.example": {}},
		Upstream:    upstream,
		Timeout:     200 * time.Millisecond,
		ClientNets:  []*net.IPNet{loopback},
		MaxInflight: 2,
	})
}

func TestBlockedQueries(t *testing.T) {
	handler := localHandler("127.0.0.1:1")
	for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
		request := new(dns.Msg)
		request.SetQuestion("Sub.Ads.Example.", queryType)
		writer := &captureWriter{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
		handler.ServeDNS(writer, request)
		if writer.msg == nil || writer.msg.Rcode != dns.RcodeNameError || writer.msg.Id != request.Id || writer.msg.AuthenticatedData || len(writer.msg.Ns) != 1 {
			t.Fatalf("unexpected blocked reply: %v", writer.msg)
		}
	}
}

func TestRejectedQueries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ip        string
		questions int
		opcode    int
		want      int
	}{
		{name: "outside network", ip: "192.0.2.1", questions: 1, opcode: dns.OpcodeQuery, want: dns.RcodeRefused},
		{name: "no question", ip: "127.0.0.1", questions: 0, opcode: dns.OpcodeQuery, want: dns.RcodeFormatError},
		{name: "multiple questions", ip: "127.0.0.1", questions: 2, opcode: dns.OpcodeQuery, want: dns.RcodeFormatError},
		{name: "update", ip: "127.0.0.1", questions: 1, opcode: dns.OpcodeUpdate, want: dns.RcodeNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion("example.org.", dns.TypeA)
			request.Opcode = tc.opcode
			if tc.questions == 0 {
				request.Question = nil
			}
			if tc.questions == 2 {
				request.Question = append(request.Question, request.Question[0])
			}
			writer := &captureWriter{addr: &net.UDPAddr{IP: net.ParseIP(tc.ip), Port: 1234}}
			localHandler("127.0.0.1:1").ServeDNS(writer, request)
			if writer.msg == nil || writer.msg.Rcode != tc.want {
				t.Fatalf("unexpected reply: %v", writer.msg)
			}
		})
	}
}

// Exercise actual UDP and TCP exchanges, including a truncated UDP upstream
// answer that requires TCP retry, and allowlist precedence over a blocked parent.
func TestForwarding(t *testing.T) {
	upstreamHandler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if _, ok := writer.RemoteAddr().(*net.UDPAddr); ok {
			reply.Truncated = true
		} else {
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				A: net.ParseIP("192.0.2.42"),
			}}
		}
		_ = writer.WriteMsg(reply)
	})
	upstreamAddress := startTestUpstream(t, upstreamHandler)
	handler := localHandler(upstreamAddress)
	handler.config.Timeout = time.Second
	for _, transport := range []string{"udp", "tcp"} {
		for _, name := range []string{"example.org.", "safe.ads.example."} {
			var addr net.Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
			if transport == "tcp" {
				addr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
			}
			writer := &captureWriter{addr: addr}
			request := new(dns.Msg)
			request.SetQuestion(name, dns.TypeA)
			handler.ServeDNS(writer, request)
			if writer.msg == nil || writer.msg.Rcode != dns.RcodeSuccess || writer.msg.Truncated || len(writer.msg.Answer) != 1 || writer.msg.Id != request.Id {
				t.Fatalf("%s %s: %v", transport, name, writer.msg)
			}
		}
	}
}

// startTestUpstream runs a local resolver on both protocols until test cleanup.
func startTestUpstream(t *testing.T, handler dns.Handler) string {
	t.Helper()
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	tcpListener, err := net.Listen("tcp", udpConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpListener.Close() })

	started := make(chan struct{}, 2)
	serverErrors := make(chan error, 2)
	servers := []*dns.Server{
		{PacketConn: udpConn, Handler: handler},
		{Listener: tcpListener, Handler: handler},
	}
	for _, server := range servers {
		server.NotifyStartedFunc = func() { started <- struct{}{} }
		go func() { serverErrors <- server.ActivateAndServe() }()
	}
	startupTimeout := time.NewTimer(time.Second)
	defer startupTimeout.Stop()
	for range servers {
		select {
		case <-started:
		case err := <-serverErrors:
			t.Fatalf("upstream startup: %v", err)
		case <-startupTimeout.C:
			t.Fatal("upstream startup timed out")
		}
	}
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Shutdown()
		}
	})
	return udpConn.LocalAddr().String()
}

func TestUpstreamFailureAndCapacity(t *testing.T) {
	handler := localHandler("127.0.0.1:1")
	for _, full := range []bool{false, true} {
		if full {
			handler.querySlots <- struct{}{}
			handler.querySlots <- struct{}{}
		}
		request := new(dns.Msg)
		request.SetQuestion("example.org.", dns.TypeA)
		writer := &captureWriter{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
		handler.ServeDNS(writer, request)
		if writer.msg == nil || writer.msg.Rcode != dns.RcodeServerFailure {
			t.Fatalf("unexpected reply %v", writer.msg)
		}
	}
}
