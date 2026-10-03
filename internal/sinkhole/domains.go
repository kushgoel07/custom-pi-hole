package sinkhole

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Domains stores domain names without capital letters or a trailing dot.
type Domains map[string]struct{}

// LoadDomains opens a domain list or a hosts file.
func LoadDomains(path string) (Domains, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseDomains(file)
}

// ParseDomains reads the list one line at a time and skips comments.
func ParseDomains(reader io.Reader) (Domains, error) {
	domains := make(Domains)
	scanner := bufio.NewScanner(reader)
	// Some hosts files have long lines with several domain names.
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		text, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		if net.ParseIP(fields[0]) != nil {
			// A hosts entry starts with an IP. We only need the names after it.
			fields = fields[1:]
		} else if len(fields) != 1 {
			return nil, fmt.Errorf("line %d: expected a domain or hosts entry", lineNumber)
		}
		for _, field := range fields {
			domain := normalizeDomain(field)
			if isLocalhost(domain) {
				continue
			}
			if !validDomain(domain) {
				return nil, fmt.Errorf("line %d: invalid domain %q", lineNumber, field)
			}
			domains[domain] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func isLocalhost(domain string) bool {
	switch domain {
	case "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback":
		return true
	default:
		return false
	}
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			isLetter := character >= 'a' && character <= 'z'
			isDigit := character >= '0' && character <= '9'
			if !isLetter && !isDigit && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

// Matches checks the name, then its parents: a.ads.example, ads.example, example.
func (domains Domains) Matches(name string) bool {
	name = normalizeDomain(name)
	for {
		if _, found := domains[name]; found {
			return true
		}
		_, parent, hasParent := strings.Cut(name, ".")
		if !hasParent {
			return false
		}
		name = parent
	}
}
