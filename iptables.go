package transproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/janeczku/go-ipset/ipset"
)

const (
	NAT         = "nat"
	PREROUTING  = "PREROUTING"
	OUTPUT      = "OUTPUT"
	NOPROXYLIST = "NOPROXYLIST"
)

type IPTables struct {
	iptables            *iptables.IPTables
	dnsTCPOutRule       []string
	dnsTCPRule          []string
	dnsUDPRule          []string
	httpRule            []string
	httpsRule           []string
	tcpRule             []string
	standaloneHTTPRule  []string
	standaloneHTTPSRule []string
	err                 error
	npNetworks          *ipset.IPSet
}

type IPTablesConfig struct {
	DNSToPort                  int
	HTTPToPort                 int
	HTTPSToPort                int
	TCPToPort                  int
	TCPDPorts                  []int
	PublicDNS                  string
	PreferLocalDNSReolver      bool
	ExecuteStandalone          bool
	DisableTCPProxy            bool
	DisableDNSProxy            bool
	ParameterHTTPHTTPSIptables string
	NoProxy                    NoProxy
}

func NewIPTables(c *IPTablesConfig) (*IPTables, error) {
	t, err := iptables.New()
	if err != nil {
		return nil, err
	}

	var tcpDPorts []string
	for _, v := range c.TCPDPorts {
		tcpDPorts = append(tcpDPorts, strconv.Itoa(v))
	}

	var dnsTCPOutRule []string
	if !c.DisableDNSProxy {
		if c.PublicDNS != "" {
			h, p, err := net.SplitHostPort(c.PublicDNS)
			if err != nil {
				c.PublicDNS = net.JoinHostPort(c.PublicDNS, "53")
			}
			h, p, _ = net.SplitHostPort(c.PublicDNS)
			dnsTCPOutRule = []string{NAT, OUTPUT, "-p", "tcp", "-d", h, "--dport", p, "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.TCPToPort)}
		}
	}

	phhi := strings.Split(c.ParameterHTTPHTTPSIptables, " ")

	var npNetworks *ipset.IPSet
	if c.ExecuteStandalone {
		n, err := ipset.New(NOPROXYLIST, "hash:net", &ipset.Params{})
		if err != nil {
			return nil, err
		} else {
			for _, value := range c.NoProxy.IPs {
				n.Add(value, 0)
			}
			for _, value := range c.NoProxy.CIDRs {
				n.Add(value.String(), 0)
			}
		}
		npNetworks = n
	}

	var dnsTCPRule []string
	var dnsUDPRule []string
	var httpRule []string
	var httpsRule []string
	var tcpRule []string
	var standaloneHTTPRule []string
	var standaloneHTTPSRule []string
	// for DNS
	if !c.DisableDNSProxy {
		if c.PreferLocalDNSReolver {
			dnsTCPRule = []string{NAT, OUTPUT, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
			dnsUDPRule = []string{NAT, OUTPUT, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
		} else {
			dnsTCPRule = []string{NAT, PREROUTING, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
			dnsUDPRule = []string{NAT, PREROUTING, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
		}
	}
	// for HTTP/HTTPS ///////////////////////////////////////////
	// for Standalone HTTP
	if c.ExecuteStandalone {
		httpRule = []string{NAT, PREROUTING, "-p", "tcp", "--dport", "80", "-m", "set", "!", "--match-set", NOPROXYLIST, "dst"}
	} else {
		httpRule = []string{NAT, PREROUTING, "-p", "tcp", "--dport", "80"}
	}
	for _, value := range phhi {
		if value == "" {
			continue
		}
		httpRule = append(httpRule, value)
	}
	httpRule = append(httpRule, []string{"-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPToPort)}...)
	// for Standalone HTTPS
	if c.ExecuteStandalone {
		httpsRule = []string{NAT, PREROUTING, "-p", "tcp", "--dport", "443", "-m", "set", "!", "--match-set", NOPROXYLIST, "dst"}
	} else {
		httpsRule = []string{NAT, PREROUTING, "-p", "tcp", "--dport", "443"}
	}
	for _, value := range phhi {
		if value == "" {
			continue
		}
		httpsRule = append(httpsRule, value)
	}
	httpsRule = append(httpsRule, []string{"-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPSToPort)}...)
	// for Standalone HTTP/HTTPS
	if c.ExecuteStandalone {
		standaloneHTTPRule = []string{NAT, OUTPUT, "-p", "tcp", "-m", "set", "!", "--match-set", NOPROXYLIST, "dst", "--dport", "80", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPToPort)}
		standaloneHTTPSRule = []string{NAT, OUTPUT, "-p", "tcp", "-m", "set", "!", "--match-set", NOPROXYLIST, "dst", "--dport", "443", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPSToPort)}
	}
	///////////////////////////////////////////////
	// TCPIP
	if !c.DisableTCPProxy {
		tcpRule = []string{NAT, PREROUTING, "-p", "tcp", "-m", "multiport", "--dport", strings.Join(tcpDPorts, ","), "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.TCPToPort)}
	}

	return &IPTables{
		iptables:            t,
		dnsTCPOutRule:       dnsTCPOutRule,
		dnsTCPRule:          dnsTCPRule,
		dnsUDPRule:          dnsUDPRule,
		httpRule:            httpRule,
		httpsRule:           httpsRule,
		tcpRule:             tcpRule,
		standaloneHTTPRule:  standaloneHTTPRule,
		standaloneHTTPSRule: standaloneHTTPSRule,
		npNetworks:          npNetworks,
	}, nil
}

func (t *IPTables) Start() error {
	t.Check(t.dnsTCPOutRule)
	t.Check(t.dnsTCPRule)
	t.Check(t.dnsUDPRule)
	t.Check(t.httpRule)
	t.Check(t.httpsRule)
	t.Check(t.tcpRule)
	t.Check(t.standaloneHTTPRule)
	t.Check(t.standaloneHTTPSRule)

	t.insertRule(t.dnsTCPOutRule)
	t.insertRule(t.dnsTCPRule)
	t.insertRule(t.dnsUDPRule)
	t.insertRule(t.httpRule)
	t.insertRule(t.httpsRule)
	t.insertRule(t.tcpRule)
	t.insertRule(t.standaloneHTTPRule)
	t.insertRule(t.standaloneHTTPSRule)

	return t.err
}

func (t *IPTables) Stop() error {
	t.deleteRule(t.dnsTCPOutRule)
	t.deleteRule(t.dnsTCPRule)
	t.deleteRule(t.dnsUDPRule)
	t.deleteRule(t.httpRule)
	t.deleteRule(t.httpsRule)
	t.deleteRule(t.tcpRule)
	t.deleteRule(t.standaloneHTTPRule)
	t.deleteRule(t.standaloneHTTPSRule)

	if t.npNetworks.Name != "" {
		t.npNetworks.Destroy()
	}

	return t.err
}

func (t *IPTables) Show() string {
	s := fmt.Sprintf(`iptables -t %s -I %s
iptables -t %s -I %s
iptables -t %s -I %s
iptables -t %s -I %s`,
		t.httpsRule[0], strings.Join(t.httpsRule[1:], " "),
		t.httpRule[0], strings.Join(t.httpRule[1:], " "),
		t.dnsUDPRule[0], strings.Join(t.dnsUDPRule[1:], " "),
		t.dnsTCPRule[0], strings.Join(t.dnsTCPRule[1:], " "),
	)

	if len(t.tcpRule) > 0 {
		s += fmt.Sprintf(`
iptables -t %s -I %s`,
			t.tcpRule[0], strings.Join(t.tcpRule[1:], " "),
		)
	}

	if len(t.dnsTCPOutRule) > 0 {
		s += fmt.Sprintf(`
iptables -t %s -I %s`,
			t.dnsTCPOutRule[0], strings.Join(t.dnsTCPOutRule[1:], " "),
		)
	}

	if len(t.standaloneHTTPRule) > 0 {
		s += fmt.Sprintf(`
iptables -t %s -I %s`,
			t.standaloneHTTPRule[0], strings.Join(t.standaloneHTTPRule[1:], " "),
		)
	}

	if len(t.standaloneHTTPSRule) > 0 {
		s += fmt.Sprintf(`
iptables -t %s -I %s`,
			t.standaloneHTTPSRule[0], strings.Join(t.standaloneHTTPSRule[1:], " "),
		)
	}

	return s
}

func (t *IPTables) Check(rule []string) {
	if t.err != nil || len(rule) < 3 {
		return
	}

	exists, err := t.iptables.Exists(rule[0], rule[1], rule[2:]...)
	if exists {
		t.err = fmt.Errorf("Same iptables rule already exists : iptables -t %s -I %s", rule[0], strings.Join(rule[1:], " "))
	}

	if err != nil {
		t.err = fmt.Errorf("Checking iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) insertRule(rule []string) {
	if t.err != nil || len(rule) < 3 {
		return
	}

	if err := t.iptables.Insert(rule[0], rule[1], 1, rule[2:]...); err != nil {
		t.err = fmt.Errorf("Insert iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) deleteRule(rule []string) {
	// Don't skip when it has error for deleting all rules
	if len(rule) < 3 {
		return
	}

	if err := t.iptables.Delete(rule[0], rule[1], rule[2:]...); err != nil {
		t.err = fmt.Errorf("Delete iptables rule failed : %s", err.Error())
	}
}

