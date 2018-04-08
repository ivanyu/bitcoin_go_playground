package main

import (
	"encoding/binary"
	"time"
	"bytes"
	"net"
	"math/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

type payload interface {
	Serialize() []byte
}

type versionPayload struct {
	version     uint32
	timestamp   uint64
	ipRecv      net.IP
	portRecv    uint16
	ipFrom      net.IP
	portFrom    uint16
	nonce       uint64
	startHeight uint32
}

func newVersionPayload(ipRecv net.IP, portRecv uint16, ipFrom net.IP, portFrom uint16, startHeight uint32) versionPayload {
	return versionPayload{
		version:     70015,
		timestamp:   uint64(time.Now().Unix()),
		ipRecv:      ipRecv,
		portRecv:    portRecv,
		ipFrom:      ipFrom,
		portFrom:    portFrom,
		nonce:       rand.Uint64(),
		startHeight: startHeight,
	}
}

func (self versionPayload) Serialize() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, self.version)
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	binary.Write(&buf, binary.LittleEndian, self.timestamp)

	var addrServices = uint64(0)
	binary.Write(&buf, binary.BigEndian, addrServices)
	binary.Write(&buf, binary.BigEndian, self.ipRecv)
	binary.Write(&buf, binary.BigEndian, self.portRecv)
	binary.Write(&buf, binary.BigEndian, addrServices)
	binary.Write(&buf, binary.BigEndian, self.ipFrom)
	binary.Write(&buf, binary.BigEndian, self.portFrom)
	binary.Write(&buf, binary.LittleEndian, self.nonce)

	userAgentBytes := []byte("go")
	userAgentLen := encodeVariableLengthInt(uint64(len(userAgentBytes)))
	binary.Write(&buf, binary.LittleEndian, userAgentLen)
	binary.Write(&buf, binary.LittleEndian, userAgentBytes)

	binary.Write(&buf, binary.LittleEndian, self.startHeight)

	relay := false
	binary.Write(&buf, binary.LittleEndian, relay)

	return buf.Bytes()
}

func encodeVariableLengthInt(i uint64) []byte {
	var buf bytes.Buffer
	if i < 0xFD {
		binary.Write(&buf, binary.LittleEndian, uint8(i))
	} else if i <= 0xFFFF {
		binary.Write(&buf, binary.LittleEndian, 0xFD)
		binary.Write(&buf, binary.LittleEndian, uint16(i))
	} else if i <= 0xFFFFFFFF {
		binary.Write(&buf, binary.LittleEndian, 0xFE)
		binary.Write(&buf, binary.LittleEndian, uint32(i))
	} else {
		binary.Write(&buf, binary.LittleEndian, 0xFF)
		binary.Write(&buf, binary.LittleEndian, uint64(i))
	}
	return buf.Bytes()
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

func (self message) Serialize() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint32(0xD9B4BEF9))

	var commandBytes [12]byte
	copy(commandBytes[:], self.command)
	binary.Write(&buf, binary.LittleEndian, commandBytes)

	payloadBytes := self.payload.Serialize()

	binary.Write(&buf, binary.LittleEndian, uint32(len(payloadBytes)))

	hashInternal := sha256.New()
	hashInternal.Write(payloadBytes)
	hashExternal := sha256.New()
	hashExternal.Write(hashInternal.Sum(nil))
	checksum := hashExternal.Sum(nil)[0:4]
	binary.Write(&buf, binary.LittleEndian, checksum)

	binary.Write(&buf, binary.LittleEndian, self.payload.Serialize())

	return buf.Bytes()
}

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

	ips, err := net.LookupIP(seed)
	if err != nil {
		return nil, err
	}

	var ip = ips[rand.Intn(len(ips))]
	return ip, nil
}

func main() {
	const bitcoinPort = 8333

	rand.Seed(time.Now().Unix())

	var ipSeed, err = getSeedIpAddress()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("IP:", ipSeed)

	var ipRecv = ipSeed
	ipFrom := net.IPv4(127, 0, 0, 1)

	startHeight := uint32(0)
	payload := newVersionPayload(ipRecv, bitcoinPort, ipFrom, bitcoinPort, startHeight)
	message := newMessage("version", payload)

	connectTo := fmt.Sprintf("%s:%d", ipRecv, bitcoinPort)
	fmt.Println("Connecting to", connectTo)

	conn, err := net.Dial("tcp", connectTo)
	defer conn.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Connected, sending version message")

	_, err = conn.Write(message.Serialize())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	recvBuf := make([]byte, 1024, 1024)
	conn.Read(recvBuf)
	fmt.Printf("% x", recvBuf)
}
