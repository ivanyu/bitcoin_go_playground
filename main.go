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
	"errors"
)

const (
	magic = uint32(0xD9B4BEF9)

	maxCommandLength = 12
	payloadChecksumLength = 4
	nonceLength = 8
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

func (v versionPayload) Serialize() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, v.version)
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	binary.Write(&buf, binary.LittleEndian, v.timestamp)

	var addrServices = uint64(0)
	binary.Write(&buf, binary.LittleEndian, addrServices)
	binary.Write(&buf, binary.BigEndian, v.ipRecv)
	binary.Write(&buf, binary.BigEndian, v.portRecv)
	binary.Write(&buf, binary.LittleEndian, addrServices)
	binary.Write(&buf, binary.BigEndian, v.ipFrom)
	binary.Write(&buf, binary.BigEndian, v.portFrom)
	binary.Write(&buf, binary.LittleEndian, v.nonce)

	userAgentBytes := []byte("go")
	userAgentLen := encodeVariableLengthInt(uint64(len(userAgentBytes)))
	binary.Write(&buf, binary.LittleEndian, userAgentLen)
	binary.Write(&buf, binary.LittleEndian, userAgentBytes)

	binary.Write(&buf, binary.LittleEndian, v.startHeight)

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

func (m message) Serialize() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, magic)

	var commandBytes [maxCommandLength]byte
	copy(commandBytes[:], m.command)
	binary.Write(&buf, binary.LittleEndian, commandBytes)

	payloadBytes := m.payload.Serialize()

	binary.Write(&buf, binary.LittleEndian, uint32(len(payloadBytes)))

	checksum := checksum(payloadBytes)
	binary.Write(&buf, binary.LittleEndian, checksum)

	binary.Write(&buf, binary.LittleEndian, m.payload.Serialize())

	return buf.Bytes()
}

func checksum(bytes []byte) []byte {
	return dhash(bytes)[0:payloadChecksumLength]
}

func dhash(bytes []byte) []byte {
	hashInternal := sha256.New()
	hashInternal.Write(bytes)
	hashExternal := sha256.New()
	hashExternal.Write(hashInternal.Sum(nil))
	return hashExternal.Sum(nil)
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

type messageHeader struct {
	command string
	length uint32
	checksum []byte
}

func readMessageHeader(buf *bytes.Buffer) (*messageHeader, error) {
	var header = new(messageHeader)

	var recvMagic uint32
	err := binary.Read(buf, binary.LittleEndian, &recvMagic)
	if err != nil {
		return nil, err
	}

	if recvMagic != magic {
		return nil, errors.New(fmt.Sprintf("received magic is %d, expected %d", recvMagic, magic))
	}

	// Read command
	var commandBytes = make([]byte, maxCommandLength, maxCommandLength)
	err = binary.Read(buf, binary.LittleEndian, &commandBytes)
	if err != nil {
		return nil, err
	}
	command, err := decodeNullTerminatedString(commandBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode command: %s", err.Error()))
	}
	fmt.Printf("Command: %s\n", command)
	header.command = command

	if command != "version" {
		return nil, errors.New(fmt.Sprintf("unsupported command %s", command))
	}

	// Read payload length
	var payloadLen uint32
	err = binary.Read(buf, binary.LittleEndian, &payloadLen)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot read payload length: %s", err.Error()))
	}
	fmt.Printf("Payload length: %d\n", payloadLen)
	header.length = payloadLen

	// Read payload checksum
	var payloadChecksumBytes = make([]byte, payloadChecksumLength, payloadChecksumLength)
	err = binary.Read(buf, binary.LittleEndian, &payloadChecksumBytes)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Payload checksum: % x\n", payloadChecksumBytes)
	header.checksum = payloadChecksumBytes

	return header, nil
}

func decodeNullTerminatedString(bytes []byte) (string, error) {
	var i = 0
	var foundNull = false
	for i < len(bytes) {
		if bytes[i] == 0 {
			foundNull = true
			break
		}
		i += 1
	}

	if foundNull {
		return string(bytes[:i]), nil
	} else {
		return "", errors.New("null terminator not found")
	}
}

func decodeVersionPayload(header *messageHeader, buf *bytes.Buffer) error {
	var payloadBytes = make([]byte, header.length, header.length)
	err := binary.Read(buf, binary.LittleEndian, &payloadBytes)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot read payload: %s", err.Error()))
	}

	var actualChecksum = checksum(payloadBytes)
	if !bytes.Equal(actualChecksum, header.checksum) {
		return errors.New("incorrect checksum")
	}

	var payloadBuf = bytes.NewBuffer(payloadBytes)
	return decodeVersionPayloadAfterCheck(payloadBuf)
}

func decodeVersionPayloadAfterCheck(buf *bytes.Buffer) error {
	// Read protocol version
	var protocolVersion uint32
	err := binary.Read(buf, binary.LittleEndian, &protocolVersion)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode protocol version: %s", err.Error()))
	}
	fmt.Printf("Protocol version: %d\n", protocolVersion)

	// Read node services
	var services = make([]byte, 8, 8)
	err = binary.Read(buf, binary.LittleEndian, &services)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode services: %s", err.Error()))
	}
	fmt.Printf("Node services: % x\n", services)

	// Read node timestamp
	var timestamp uint64
	err = binary.Read(buf, binary.LittleEndian, &timestamp)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode timestamp: %s", err.Error()))
	}
	fmt.Printf("Node timestamp: %d == %s\n", timestamp, time.Unix(int64(timestamp), 0))

	servicesRecv, ipRecv, portRecv, err := decodeNodeServicesAddressAndPort(buf)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	fmt.Printf("Receiving node services: % x\n", servicesRecv)
	fmt.Printf("Receiving node IP and port: %s:%d\n", ipRecv, portRecv)

	servicesEmit, ipEmit, portEmit, err := decodeNodeServicesAddressAndPort(buf)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	fmt.Printf("Emitting node services: % x\n", servicesEmit)
	fmt.Printf("Emitting node IP and port: %s:%d\n", ipEmit, portEmit)

	var nonce = make([]byte, nonceLength, nonceLength)
	err = binary.Read(buf, binary.LittleEndian, &nonce)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode nonce: %s", err.Error()))
	}
	fmt.Printf("Nonce: % x\n", nonce)

	userAgent, err := decodeUserAgent(buf)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode user agent: %s", err.Error()))
	}
	fmt.Printf("User agent: %s\n", userAgent)

	var height uint32
	err = binary.Read(buf, binary.LittleEndian, &height)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode block start height: %s", err.Error()))
	}
	fmt.Printf("Block start height: %d\n", height)

	var relay bool
	err = binary.Read(buf, binary.LittleEndian, &relay)
	if err != nil {
		return errors.New(fmt.Sprintf("cannot decode relay flag: %s", err.Error()))
	}
	fmt.Printf("Relay flag: %t\n", relay)

	return nil
}

func decodeNodeServicesAddressAndPort(buf *bytes.Buffer) ([]byte, net.IP, uint16, error) {
	// Read node services
	var services = make([]byte, 8, 8)
	var ip net.IP
	var port = uint16(0)

	err := binary.Read(buf, binary.LittleEndian, &services)
	if err != nil {
		return services, ip, port, errors.New(fmt.Sprintf("cannot read services: %s", err.Error()))
	}

	var ipArr = make([]byte, net.IPv6len, net.IPv6len)
	err = binary.Read(buf, binary.BigEndian, &ipArr)
	if err != nil {
		return services, ip, port, errors.New(fmt.Sprintf("cannot read IP: %s", err.Error()))
	}
	ip = net.IP(ipArr)

	err = binary.Read(buf, binary.BigEndian, &port)
	if err != nil {
		return services, ip, port, errors.New(fmt.Sprintf("cannot read port: %s", err.Error()))
	}

	return services, ip, port, nil
}

func decodeUserAgent(buf *bytes.Buffer) (string, error) {
	length, err := readVariableLengthInt(buf)
	if err != nil {
		return "", err
	}
	fmt.Printf("User agent length: %d\n", length)

	uaArr := make([]byte, length, length)
	err = binary.Read(buf, binary.LittleEndian, &uaArr)
	if err != nil {
		return "", err
	}

	return string(uaArr), nil
}

func readVariableLengthInt(buf *bytes.Buffer) (uint64, error) {
	var marker uint8
	err := binary.Read(buf, binary.LittleEndian, &marker)
	if err != nil {
		return 0, err
	}

	if marker < 0xFD {
		return uint64(marker), nil
	} else if marker == 0xFD {
		var n uint16
		err := binary.Read(buf, binary.LittleEndian, &n)
		if err != nil {
			return 0, err
		}
		return uint64(n), nil
	} else if marker == 0xFE {
		var n uint32
		err := binary.Read(buf, binary.LittleEndian, &n)
		if err != nil {
			return 0, err
		}
		return uint64(n), nil
	} else {
		var n uint64
		err := binary.Read(buf, binary.LittleEndian, &n)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
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

	recvArr := make([]byte, 1024, 1024)
	recvBuf := bytes.NewBuffer(make([]byte, 0, 1024))
	var readingHeader = true
	var header *messageHeader = nil
	for true {
		readBytes, err := conn.Read(recvArr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// fmt.Printf("Read %d bytes\n", readBytes)
		recvBuf.Write(recvArr[:readBytes])

		if readingHeader {
			if recvBuf.Len() >= 24 {
				header, err = readMessageHeader(recvBuf)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				// fmt.Println(header)

				readingHeader = false
			}
		} else {
			if uint32(recvBuf.Len()) >= header.length {
				switch header.command {
				case "version":
					err = decodeVersionPayload(header, recvBuf)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				}

				readingHeader = true
				header = nil
			}
		}
	}
}
