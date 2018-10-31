package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	transproxy "go-transproxy/go-transproxy"

	"github.com/comail/colog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

var (
	confFile = *flag.String(
		"conf",
		"/etc/transproxy/transproxy.conf",
		"Config file.",
	)

	loglevelLocal = *flag.String(
		"loglevel-local",
		"info",
		"Log level, one of: debug, info, warn, error, fatal, panic",
	)

	privateDNS = *flag.String("private-dns", "",
		"Private DNS address for no_proxy targets (IP[:port])")

	publicDNS = *flag.String("public-dns", "",
		"Public DNS address (IP[:port]) Note: Your proxy needs to support CONNECT method to the Public DNS port, and the public DNS needs to support TCP")

	tcpProxyDestPorts = *flag.String(
		"tcp-proxy-dports", "22", "TCP Proxy dports, as `port1,port2,...`",
	)

	tcpProxyListenAddress = *flag.String(
		"tcp-proxy-listen", ":3128", "TCP Proxy listen address, as `[host]:port`",
	)

	httpProxyListenAddress = *flag.String(
		"http-proxy-listen", ":3129", "HTTP Proxy listen address, as `[host]:port`",
	)

	httpsProxyListenAddress = *flag.String(
		"https-proxy-listen", ":3130", "HTTPS Proxy listen address, as `[host]:port`",
	)

	dnsProxyListenAddress = *flag.String(
		"dns-proxy-listen", ":3131", "DNS Proxy listen address, as `[host]:port`",
	)

	explicitProxyListenAddress = *flag.String(
		"explicit-proxy-listen", ":3132", "Explicit Proxy listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy doesn't use authentication info of the `http_proxy` and `https_proxy` environment variables",
	)

	explicitProxyWithAuthListenAddress = *flag.String(
		"explicit-proxy-with-auth-listen", ":3133", "Explicit Proxy with auth listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy uses authentication info of the `http_proxy` and `https_proxy` environment variables",
	)

	explicitProxyOnly = *flag.Bool(
		"explicit-proxy-only", false, "Boot Explicit Proxies only",
	)

	dnsOverTCPDisabled = *flag.Bool(
		"dns-over-tcp-disabled", false, "Disable DNS-over-TCP for querying to public DNS")

	dnsOverHTTPSEnabled = *flag.Bool(
		"dns-over-https-enabled", false, "Use DNS-over-HTTPS service as public DNS")

	dnsOverHTTPSEndpoint = *flag.String(
		"dns-over-https-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP    = *flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP    = *flag.Bool("dns-udp", true, "DNS Listen on UDP")
	disableIPTables = *flag.Bool("disable-iptables", false, "Disable automatic iptables configuration")

	preferLocalDNSReolver      = *flag.Bool("prefer-local-dns-reolver", false, "If true, use the local DNS resolver preferentially. If unknown, go-transproxy will process it. (local DNS resolver, dnsmasq, systemd-resolved.....)")
	executeStandalone          = *flag.Bool("execute-standalone", false, "Set to true to execute a transparent proxy on each computer.")
	disableTCPProxy            = *flag.Bool("disable-tcpproxy", false, "Disable tcp's transproxy.")
	parameterHTTPHTTPSIptables = *flag.String(
		"parameter-http-https-iptables", "", "Specify additional parameters.(etc. '-i eth0')",
	)
	ntlmEnabled = *flag.Bool("ntlm-enabled", false, "Use NTLM authentication. (Basic authentication can not be used.)")
)

func settings() {
	loglevelLocal = viper.GetString("loglevel-local")
	privateDNS = viper.GetString("private-dns")
	publicDNS = viper.GetString("public-dns")
	tcpProxyDestPorts = viper.GetString("tcp-proxy-dports")
	tcpProxyListenAddress = viper.GetString("tcp-proxy-listen")
	httpProxyListenAddress = viper.GetString("http-proxy-listen")
	httpsProxyListenAddress = viper.GetString("https-proxy-listen")
	dnsProxyListenAddress = viper.GetString("dns-proxy-listen")
	explicitProxyListenAddress = viper.GetString("explicit-proxy-listen")
	explicitProxyWithAuthListenAddress = viper.GetString("explicit-proxy-with-auth-listen")
	explicitProxyOnly = viper.GetBool("explicit-proxy-only")
	dnsOverTCPDisabled = viper.GetBool("dns-over-tcp-disabled")
	dnsOverHTTPSEnabled = viper.GetBool("dns-over-https-enabled")
	dnsOverHTTPSEndpoint = viper.GetString("dns-over-https-endpoint")
	dnsEnableTCP = viper.GetBool("dns-tcp")
	dnsEnableUDP = viper.GetBool("dns-udp")
	disableIPTables = viper.GetBool("disable-iptables")
	preferLocalDNSReolver = viper.GetBool("prefer-local-dns-reolver")
	executeStandalone = viper.GetBool("execute-standalone")
	disableTCPProxy = viper.GetBool("disable-tcpproxy")
	parameterHTTPHTTPSIptables = viper.GetString("parameter-http-https-iptables")
	ntlmEnabled = viper.GetBool("ntlm-enabled")
}

func main() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigType("toml")
	viper.SetConfigFile(viper.GetString("conf"))
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Config Error: %s \n", err))
	}
	settings()
	log.Printf("info: %s", dnsProxyListenAddress)

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

	// setup logger
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LInfo)
	level, err := colog.ParseLevel(loglevelLocal)
	if err != nil {
		log.Fatalf("alert: Invalid log level: %s", err.Error())
	}
	colog.SetMinLevel(level)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds,
	})
	colog.ParseFields(true)
	colog.Register()

	if explicitProxyOnly {
		startExplicitProxyOnly(level)
	} else {
		startAllProxy(level)
	}
}

func startExplicitProxyOnly(level colog.Level) {
	startExplicitProxy()

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("info: Proxy servers stopping.")
	log.Printf("info: go-transproxy exited.")
}

func startAllProxy(level colog.Level) {
	// handling no_proxy environment
	noProxy := os.Getenv("no_proxy")
	if noProxy == "" {
		noProxy = os.Getenv("NO_PROXY")
	}
	if noProxy == "" {
		noProxy = "127.0.0.1"
	}

	np := parseNoProxy(noProxy)
	// start servers
	tcpProxy := transproxy.NewTCPProxy(
		transproxy.TCPProxyConfig{
			ListenAddress: tcpProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := tcpProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	dnsProxy := transproxy.NewDNSProxy(
		transproxy.DNSProxyConfig{
			Enabled:             useDNSProxy(),
			ListenAddress:       dnsProxyListenAddress,
			EnableUDP:           dnsEnableUDP,
			EnableTCP:           dnsEnableTCP,
			Endpoint:            dnsOverHTTPSEndpoint,
			PublicDNS:           publicDNS,
			PrivateDNS:          privateDNS,
			DNSOverHTTPSEnabled: dnsOverHTTPSEnabled,
			NoProxyDomains:      np.Domains,
		},
	)
	dnsProxy.Start()

	httpProxy := transproxy.NewHTTPProxy(
		transproxy.HTTPProxyConfig{
			ListenAddress: httpProxyListenAddress,
			NoProxy:       np,
			Verbose:       level == colog.LDebug,
		},
	)
	if err := httpProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	httpsProxy := transproxy.NewHTTPSProxy(
		transproxy.HTTPSProxyConfig{
			ListenAddress: httpsProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := httpsProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	startExplicitProxy()

	log.Printf("info: All proxy servers started.")

	dnsToPort := toPort(dnsProxyListenAddress)
	httpToPort := toPort(httpProxyListenAddress)
	httpsToPort := toPort(httpsProxyListenAddress)
	tcpToPort := toPort(tcpProxyListenAddress)
	tcpDPorts := toPorts(tcpProxyDestPorts)

	outgoingPublicDNS := publicDNS
	if dnsOverTCPDisabled {
		outgoingPublicDNS = ""
	}

	var t *transproxy.IPTables
	var err error

	if !disableIPTables {
		t, err = transproxy.NewIPTables(&transproxy.IPTablesConfig{
			DNSToPort:                  dnsToPort,
			HTTPToPort:                 httpToPort,
			HTTPSToPort:                httpsToPort,
			TCPToPort:                  tcpToPort,
			TCPDPorts:                  tcpDPorts,
			PublicDNS:                  outgoingPublicDNS,
			PreferLocalDNSReolver:      preferLocalDNSReolver,
			ExecuteStandalone:          executeStandalone,
			DisableTCPProxy:            disableTCPProxy,
			ParameterHTTPHTTPSIptables: parameterHTTPHTTPSIptables,
			NoProxy:                    np,
		})
		if err != nil {
			log.Printf("alert: %s", err.Error())
		}

		t.Start()

		log.Printf(`info: iptables rules inserted as follows.
---
%s
---`, t.Show())
	}

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("info: Proxy servers stopping.")

	// start shutdown process
	if !disableIPTables {
		t.Stop()
		log.Printf("info: iptables rules deleted.")
	}

	if dnsProxy != nil {
		dnsProxy.Stop()
	}

	log.Printf("info: go-transproxy exited.")
}

func startExplicitProxy() {
	explicitProxyWithAuth := transproxy.NewExplicitProxy(
		transproxy.ExplicitProxyConfig{
			ListenAddress:         explicitProxyWithAuthListenAddress,
			UseProxyAuthorization: true,
		},
	)
	if err := explicitProxyWithAuth.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	explicitProxy := transproxy.NewExplicitProxy(
		transproxy.ExplicitProxyConfig{
			ListenAddress:         explicitProxyListenAddress,
			UseProxyAuthorization: false,
		},
	)
	if err := explicitProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}
}

func useDNSProxy() bool {
	if privateDNS == "" && publicDNS == "" && dnsOverHTTPSEnabled == false {
		return false
	}
	return true
}

func toPort(addr string) int {
	array := strings.Split(addr, ":")
	if len(array) != 2 {
		log.Printf("alert: Invalid address, no port: %s", addr)
	}

	i, err := strconv.Atoi(array[1])
	if err != nil {
		log.Printf("alert: Invalid address, the port isn't number: %s", addr)
	}

	if i > 65535 || i < 0 {
		log.Printf("alert: Invalid address, the port must be an integer value in the range 0-65535: %s", addr)
	}

	return i
}

func toPorts(ports string) []int {
	array := strings.Split(ports, ",")

	var p []int

	for _, v := range array {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("alert: Invalid port, It's not number: %s", ports)
		}

		if i > 65535 || i < 0 {
			log.Printf("alert: Invalid port, It must be an integer value in the range 0-65535: %s", ports)
		}

		p = append(p, i)
	}

	return p
}

func parseNoProxy(noProxy string) transproxy.NoProxy {
	p := strings.Split(noProxy, ",")

	var ipArray []string
	var cidrArray []*net.IPNet
	var domainArray []string

	for _, v := range p {
		ip := net.ParseIP(v)
		if ip != nil {
			ipArray = append(ipArray, v)
			continue
		}

		_, ipnet, err := net.ParseCIDR(v)
		if err == nil {
			cidrArray = append(cidrArray, ipnet)
			continue
		}

		domainArray = append(domainArray, v)
	}

	return transproxy.NoProxy{
		IPs:     ipArray,
		CIDRs:   cidrArray,
		Domains: domainArray,
	}
}

