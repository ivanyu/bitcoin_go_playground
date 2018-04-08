package main

import (
	"encoding/binary"
	"time"
	"bytes"
	"net"
	"math/rand"
	"fmt"
	"os"
	"errors"
)

type receivedMessageHeader struct {
	command string
	length uint32
	checksum []byte
}

func readMessageHeader(buf *bytes.Buffer) (*receivedMessageHeader, error) {
	var header = new(receivedMessageHeader)

	var recvMagic uint32
	err := binary.Read(buf, binary.LittleEndian, &recvMagic)
	if err != nil {
		return nil, err
	}

	if recvMagic != magic {
		return nil, errors.New(fmt.Sprintf("received magic is %d, expected %d", recvMagic, magic))
	}

	// Read command
	var commandBytes = make([]byte, maxCommandLen, maxCommandLen)
	err = binary.Read(buf, binary.LittleEndian, &commandBytes)
	if err != nil {
		return nil, err
	}
	command, err := decodeNullTerminatedString(commandBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode command: %s", err.Error()))
	}
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
	header.length = payloadLen

	// Read payload checksum
	var payloadChecksumBytes = make([]byte, payloadChecksumLen, payloadChecksumLen)
	err = binary.Read(buf, binary.LittleEndian, &payloadChecksumBytes)
	if err != nil {
		return nil, err
	}
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

func decodeVersionPayload(header *receivedMessageHeader, buf *bytes.Buffer) (*versionPayload, error) {
	var payloadBytes = make([]byte, header.length, header.length)
	err := binary.Read(buf, binary.LittleEndian, &payloadBytes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot read payload: %s", err.Error()))
	}

	if !verifyChecksum(payloadBytes, header.checksum) {
		return nil, errors.New("incorrect checksum")
	}

	var payloadBuf = bytes.NewBuffer(payloadBytes)
	return decodeVersionPayloadAfterCheck(payloadBuf)
}

func decodeVersionPayloadAfterCheck(buf *bytes.Buffer) (*versionPayload, error) {
	var result = new(versionPayload)

	// Read protocol version
	err := binary.Read(buf, binary.LittleEndian, &result.version)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode protocol version: %s", err.Error()))
	}

	// Read node services
	result.services = make([]byte, servicesLen, servicesLen)
	err = binary.Read(buf, binary.LittleEndian, &result.services)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode services: %s", err.Error()))
	}

	// Read node timestamp
	err = binary.Read(buf, binary.LittleEndian, &result.timestamp)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode timestamp: %s", err.Error()))
	}

	servicesRecv, err := decodeNodeServices(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	ipRecv, err := decodeNodeAddress(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	portRecv, err := decodeNodePort(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}

	result.servicesRecv = servicesRecv
	result.ipRecv = ipRecv
	result.portRecv = portRecv

	servicesFrom, err := decodeNodeServices(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	ipFrom, err := decodeNodeAddress(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}
	portFrom, err := decodeNodePort(buf)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode receiving node address: %s", err.Error()))
	}

	result.servicesFrom = servicesFrom
	result.ipFrom = ipFrom
	result.portFrom = portFrom

	err = binary.Read(buf, binary.LittleEndian, &result.nonce)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode nonce: %s", err.Error()))
	}

	result.userAgent, err = decodeUserAgent(buf)
	if err != nil {
		return result, errors.New(fmt.Sprintf("cannot decode user agent: %s", err.Error()))
	}

	err = binary.Read(buf, binary.LittleEndian, &result.startHeight)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode block start height: %s", err.Error()))
	}

	err = binary.Read(buf, binary.LittleEndian, &result.relay)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cannot decode relay flag: %s", err.Error()))
	}

	return result, nil
}

func decodeNodeServices(buf *bytes.Buffer) ([]byte, error) {
	var services = make([]byte, servicesLen, servicesLen)
	err := binary.Read(buf, binary.LittleEndian, &services)
	if err != nil {
		return services, errors.New(fmt.Sprintf("cannot read services: %s", err.Error()))
	}
	return services, nil
}

func decodeNodeAddress(buf *bytes.Buffer) (net.IP, error) {
	var ip net.IP

	var ipArr = make([]byte, net.IPv6len, net.IPv6len)
	err := binary.Read(buf, binary.BigEndian, &ipArr)
	if err != nil {
		return ip, errors.New(fmt.Sprintf("cannot read IP: %s", err.Error()))
	}
	ip = net.IP(ipArr)

	return ip, nil
}

func decodeNodePort(buf *bytes.Buffer) (uint16, error) {
	var port = uint16(0)
	err := binary.Read(buf, binary.BigEndian, &port)
	if err != nil {
		return port, errors.New(fmt.Sprintf("cannot read port: %s", err.Error()))
	}
	return port, nil
}

func decodeUserAgent(buf *bytes.Buffer) (string, error) {
	length, err := readVariableLengthInt(buf)
	if err != nil {
		return "", err
	}
	// fmt.Printf("User agent length: %d\n", length)

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
	payload := newVersionPayload(ipRecv, bitcoinPort, ipFrom, bitcoinPort, "go", startHeight, false)
	message := newMessage("version", payload)

	connectTo := fmt.Sprintf("%s:%d", ipRecv, bitcoinPort)
	fmt.Println("Connecting to", connectTo)

	conn, err := net.Dial("tcp", connectTo)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected, sending version message")

	_, err = conn.Write(message.Serialize())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	recvArr := make([]byte, 1024, 1024)
	recvBuf := bytes.NewBuffer(make([]byte, 0, 1024))
	var readingHeader = true
	var header *receivedMessageHeader = nil
	for true {
		if readingHeader {
			recvBuf.Reset()
		}

		readBytes, err := conn.Read(recvArr)
		if err != nil {
			fmt.Printf("Error reading bytes: %s\n", err)
			os.Exit(1)
		}
		// fmt.Printf("Read %d bytes\n", readBytes)
		recvBuf.Write(recvArr[:readBytes])

		for true {
			// fmt.Println("Available1:", recvBuf.Len())
			if readingHeader {
				if recvBuf.Len() >= 24 {
					header, err = readMessageHeader(recvBuf)
					if err != nil {
						fmt.Printf("Error reading header: %s\n", err)
						os.Exit(1)
					}
					// fmt.Println("Available2:", recvBuf.Len())
					fmt.Println(header)
					// fmt.Printf("Command: %s\n", header.command)
					// fmt.Printf("Payload length: %d\n", header.length)
					// fmt.Printf("Payload checksum: % x\n", header.checksum)

					readingHeader = false
				} else {
					break
				}
			} else {
				if uint32(recvBuf.Len()) >= header.length {
					switch header.command {
					case "version":
						payload, err := decodeVersionPayload(header, recvBuf)
						if err != nil {
							fmt.Printf("Error reading payload: %s\n", err)
							os.Exit(1)
						}
						// fmt.Println("Available2:", recvBuf.Len())
						fmt.Println(payload)
						// fmt.Printf("Protocol version: %d\n", payload.version)
						// fmt.Printf("Node services: % x\n", payload.services)
						// fmt.Printf("Node timestamp: %d == %s\n", payload.timestamp, time.Unix(int64(payload.timestamp), 0))
						// fmt.Printf("Receiving node services: % x\n", payload.servicesRecv)
						// fmt.Printf("Receiving node IP and port: %s:%d\n", ipRecv, payload.portRecv)
						// fmt.Printf("Emitting node services: % x\n", payload.servicesFrom)
						// fmt.Printf("Emitting node IP and port: %s:%d\n", ipFrom, payload.portFrom)
						// fmt.Printf("Nonce: %d\n", payload.nonce)
						// fmt.Printf("User agent: %s\n", payload.userAgent)
						// fmt.Printf("Block start height: %d\n", payload.startHeight)
						// fmt.Printf("Relay flag: %t\n", payload.relay)
					}

					readingHeader = true
					header = nil
				} else {
					break
				}
			}
		}
	}
}
