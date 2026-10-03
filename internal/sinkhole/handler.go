package sinkhole

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const negativeCacheTTL = 60

// HandlerConfig holds the lists and DNS settings.
// Use positive Timeout and MaxInflight values and don't change lists while serving.
type HandlerConfig struct {
	Blocked     Domains
	Allowed     Domains
	Upstream    string
	Timeout     time.Duration
	ClientNets  []*net.IPNet
	MaxInflight int
}

// Handler blocks listed domains and forwards the rest.
type Handler struct {
	config     HandlerConfig
	querySlots chan struct{}
}

// NewHandler sets up the limit on active upstream queries.
func NewHandler(config HandlerConfig) *Handler {
	return &Handler{
		config:     config,
		querySlots: make(chan struct{}, config.MaxInflight),
	}
}

func (h *Handler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	if !h.permitsClient(writer.RemoteAddr()) {
		writeError(writer, request, dns.RcodeRefused)
		return
	}
	if request.Opcode != dns.OpcodeQuery {
		writeError(writer, request, dns.RcodeNotImplemented)
		return
	}
	if len(request.Question) != 1 {
		writeError(writer, request, dns.RcodeFormatError)
		return
	}

	question := request.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		writeError(writer, request, dns.RcodeRefused)
		return
	}
	if h.config.Blocked.Matches(question.Name) && !h.config.Allowed.Matches(question.Name) {
		_ = writer.WriteMsg(blockedReply(request))
		return
	}

	// Each item in this channel is one active query. Don't queue extra queries.
	select {
	case h.querySlots <- struct{}{}:
		defer func() { <-h.querySlots }()
	default:
		writeError(writer, request, dns.RcodeServerFailure)
		return
	}

	transport := "udp"
	if _, isTCP := writer.RemoteAddr().(*net.TCPAddr); isTCP {
		transport = "tcp"
	}
	answer, err := h.forward(request, transport)
	if err != nil || !matchesRequest(answer, request) {
		writeError(writer, request, dns.RcodeServerFailure)
		return
	}

	answer.Id = request.Id
	if transport == "udp" {
		// DNS uses 512 bytes unless the client asks for a larger UDP response.
		size := dns.MinMsgSize
		if edns := request.IsEdns0(); edns != nil && int(edns.UDPSize()) > size {
			size = int(edns.UDPSize())
		}
		answer.Truncate(size)
	}
	_ = writer.WriteMsg(answer)
}

func (h *Handler) permitsClient(address net.Addr) bool {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	for _, network := range h.config.ClientNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func writeError(writer dns.ResponseWriter, request *dns.Msg, code int) {
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.RecursionAvailable = true
	reply.Rcode = code
	_ = writer.WriteMsg(reply)
}

func blockedReply(request *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.RecursionAvailable = true
	reply.Rcode = dns.RcodeNameError
	// This tells clients to remember the blocked result for 60 seconds.
	reply.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name:   request.Question[0].Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    negativeCacheTTL,
		},
		Ns:      "sinkhole.invalid.",
		Mbox:    "hostmaster.invalid.",
		Serial:  1,
		Refresh: negativeCacheTTL,
		Retry:   negativeCacheTTL,
		Expire:  negativeCacheTTL,
		Minttl:  negativeCacheTTL,
	}}
	return reply
}

func (h *Handler) forward(request *dns.Msg, transport string) (*dns.Msg, error) {
	// Both attempts share the same timeout.
	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()

	client := &dns.Client{Net: transport, Timeout: h.config.Timeout}
	answer, _, err := client.ExchangeContext(ctx, request.Copy(), h.config.Upstream)
	if err == nil && answer != nil && answer.Truncated && transport == "udp" {
		client.Net = "tcp"
		answer, _, err = client.ExchangeContext(ctx, request.Copy(), h.config.Upstream)
	}
	return answer, err
}

func matchesRequest(answer, request *dns.Msg) bool {
	if answer == nil || !answer.Response || answer.Opcode != request.Opcode || len(answer.Question) != 1 {
		return false
	}
	actual := answer.Question[0]
	expected := request.Question[0]
	return actual.Qtype == expected.Qtype &&
		actual.Qclass == expected.Qclass &&
		strings.EqualFold(actual.Name, expected.Name)
}
