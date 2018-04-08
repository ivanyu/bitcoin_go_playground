package main

import (
	"net"
	"math/rand"
	"fmt"
)

func getSeedIpAddress() (net.IP, error) {
	var seeds = []string{
		"seed.bitcoin.sipa.be",
		"dnsseed.bluematt.me",
		"dnsseed.bitcoin.dashjr.org",
		"seed.bitcoinstats.com",
		"seed.bitcoin.jonasschnelli.ch",
		"seed.btc.petertodd.org",
		"seed.bitcoin.sprovoost.nl"}
	var seed = seeds[rand.Intn(len(seeds))]
	fmt.Println("Seed:", seed)

	var ips []net.IP
	i := 0
	for true {
		ips0, err := net.LookupIP(seed)
		if err == nil {
			ips = ips0
			break
		}

		if i == 2 {
			return nil, err
		}
		i += 1
	}

	var ip = ips[rand.Intn(len(ips))]
	return ip, nil
}

