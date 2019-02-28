# go-transproxy for RDBOX

forked from [wadahiro/go\-transproxy](https://github.com/wadahiro/go-transproxy)
The major design pattern of this software was abstracted from wadahiro's go-transproxy, which is subject to the same license.

Transparent proxy servers for HTTP, HTTPS, DNS and TCP. 
This repository is heavily under development.

<img src="https://github.com/fukuta-tatsuya-intec/go-transproxy/blob/master/images/kougakumeisai.png" width="200px">

## Description

**go-transproxy** provides transparent proxy servers for HTTP, HTTPS, DNS and TCP with single binary.
Nothing needs to setup many tools. Nothing needs to configure iptables.
**go-transproxy** will start multiple proxy servers for these protocols.
Futheremore, it will configure iptables automatically.

**go-transproxy** also provides two types of explicit proxy(not transparent proxy).
One is a simple proxy delegating to upstream your proxy, another is for adding `Proxy-Authorization` header automatically.

## Requirement

**go-transproxy** supports only Linux iptables.

## Changes from the original version.

* deb packaging
* Systemctl daemonization
* Read settings from setting file.
* add logging settings.
* iptables item specialized in RDBOX.(It can also be disabled.)

## Getting Started.
1. Install
```
wget -qO - "https://bintray.com/user/downloadSubjectPublicKey?username=rdbox" | sudo apt-key add - 
echo "deb https://dl.bintray.com/rdbox/deb stretch main" | sudo tee -a /etc/apt/sources.list.d/rdbox.list
sudo apt-get update
sudo apt-get install transproxy
```

1. In order to activate transproxyService, create two new files, http_proxy and no_proxy.

- /etc/transproxy/http_proxy
Create new one. and set your proxy environment.
```
http_proxy=http://user:pass@yourproxy.example.org:8080
```

- /etc/transproxy/no_proxy
Create new one. make sure to configure the 127.0.0.1
```
no_proxy=127.0.0.1,192.168.0.0/24
```

- /etc/transproxy/transproxy.conf

```
## Log level, one of: debug, info, warn, error, fatal, panic
## default:info
## type:string
loglevel-local = "info"

## Private DNS address for no_proxy targets (IP[:port])
## default:""(empty string)
## type:string
private-dns = ""

## Public DNS address (IP[:port]) Note: Your proxy needs to support CONNECT method to the Public DNS port, and the public DNS needs to support TCP
## default:""(empty string)
## type:string
public-dns = ""

## TCP Proxy dports, as "port1,port2,..."
## default:"22"
## type:string
tcp-proxy-dports = "22"

## TCP Proxy listen address, as "[host]:port"
## default:":3128"
## type:string
tcp-proxy-listen = ":3128"

## HTTP Proxy listen addres, as "[host]:port"
## default:":3129"
## type:string
http-proxy-listen = ":3129"

## HTTPS Proxy listen addres, as "[host]:port"
## default:":3130"
## type:string
https-proxy-listen = ":3130"

## DNS Proxy listen addres, as "[host]:port"
## default:":3130"
## type:string
dns-proxy-listen = ":3131"

## Explicit Proxy listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy doesn't use authentication info of the `http_proxy` and `https_proxy` environment variables
## default:":3132"
## type:string
explicit-proxy-listen = ":3132"

## Explicit Proxy with auth listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy uses authentication info of the `http_proxy` and `https_proxy` environment variables
## default:":3133"
## type:string
explicit-proxy-with-auth-listen = ":3133"

## Boot Explicit Proxies only"
## default:false
## type:bool
explicit-proxy-only = false

## Disable DNS-over-TCP for querying to public DNS
## default:false
## type:bool
dns-over-tcp-disabled = false

## Use DNS-over-HTTPS service as public DNS
## default:false
## type:bool
dns-over-https-enabled = false

## DNS-over-HTTPS endpoint URL
## default:"https://dns.google.com/resolve"
## type:string
dns-over-https-endpoint = "https://dns.google.com/resolve"

## DNS Listen on TCP
## default:true
## type:bool
dns-tcp = true

## DNS Listen on UDP
## default:true
## type:bool
dns-udp = true

## Disable automatic iptables configuration
## default:false
## type:bool
disable-iptables = false

## If true, use the local DNS resolver preferentially. If unknown hostname, transproxy will process it. (local DNS resolver, dnsmasq, systemd-resolved.....)
## default:false
## type:bool
prefer-local-dns-reolver = false

## Set to true to execute a transparent proxy on each computer.
## default:false
## type:bool
execute-standalone = false

## Disable tcp's transproxy.
## default:false
## type:bool
disable-tcpproxy = false

## Disable dns's transproxy.
## default:false
## type:bool
disable-dnsproxy = false

## Specify additional parameters.(etc. "-i eth0")
## default:""(empty string)
## type:string
parameter-http-https-iptables = ""
```

1. restart a service

```bash
# with admin privileges(sudo)
sudo systemctl stop transproxy.service 
sudo systemctl start transproxy.service 
```

1. log file is here
```bash
$ sudo tail -f /var/log/transproxy/transproxy.log
```


## Current Limitation

* HTTP proxy: Only works with HTTP host header.
* HTTPS proxy: `no_proxy` only works with IP Address and CIDR if your https client doesn't support [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).
* TCP proxy: `no_proxy` only works with IP Address and CIDR.

## Licence

Licensed under the [MIT](/LICENSE) license.

