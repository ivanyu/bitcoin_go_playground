package main

import (
	"net"
	"math/rand"
	"time"
)

type payload interface {
	Serialize() []byte
}

type versionPayload struct {
	version      uint32
	services     []byte
	timestamp    uint64
	servicesRecv []byte
	ipRecv       net.IP
	portRecv     uint16
	servicesFrom []byte
	ipFrom       net.IP
	portFrom     uint16
	nonce        uint64
	userAgent    string
	startHeight  uint32
	relay        bool
}

func newVersionPayload(
	ipRecv net.IP, portRecv uint16, ipFrom net.IP, portFrom uint16, userAgent string, startHeight uint32, relay bool) versionPayload {
	return versionPayload{
		version:      70015,
		services:     make([]byte, servicesLen, servicesLen),
		timestamp:    uint64(time.Now().Unix()),
		servicesRecv: make([]byte, servicesLen, servicesLen),
		ipRecv:       ipRecv,
		portRecv:     portRecv,
		servicesFrom: make([]byte, servicesLen, servicesLen),
		ipFrom:       ipFrom,
		portFrom:     portFrom,
		nonce:        rand.Uint64(),
		userAgent:    userAgent,
		startHeight:  startHeight,
		relay:        relay,
	}
}

type message struct {
	command string
	payload payload
}

func newMessage(command string, p payload) message {
	return message{
		command: command,
		payload: p,
	}
}
