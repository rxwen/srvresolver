package srvresolver

import (
	"errors"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

func ResolveSRV(record string) (ip string, port string, err error) {
	config, _ := dns.ClientConfigFromFile("etc/resolv.conf")

	qType, _ := dns.StringToType["SRV"]
	name := dns.Fqdn(record)

	client := &dns.Client{Net: ""}
	msg := &dns.Msg{}
	msg.SetQuestion(name, qType)
	response, _, err := client.Exchange(msg, config.Servers[0]+":"+config.Port)
	if err != nil {
		return "", "", err
	}
	srvs := make([]net.SRV, 0)
	for _, v := range response.Answer {
		if srv, ok := v.(*dns.SRV); ok {
			target := srv.Target
			for _, v := range response.Extra {
				// check if there is additional A record for the node
				if a, ok := v.(*dns.A); ok && a.Hdr.Name == target {
					target = a.A.String()
				}
			}
			srvs = append(srvs, net.SRV{
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   target,
			})
		}
	}

	if len(srvs) == 0 {
		return "", "", errors.New("no record found for SRV")
	}

	return srvs[0].Target, strconv.Itoa(int(srvs[0].Port)), nil
}
