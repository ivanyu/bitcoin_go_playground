package main

import (
	"bytes"
	"encoding/binary"
)

func (v versionPayload) Serialize() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, v.version)
	binary.Write(&buf, binary.LittleEndian, uint64(0))
	binary.Write(&buf, binary.LittleEndian, v.timestamp)

	binary.Write(&buf, binary.LittleEndian, v.servicesRecv)
	binary.Write(&buf, binary.BigEndian, v.ipRecv)
	binary.Write(&buf, binary.BigEndian, v.portRecv)
	binary.Write(&buf, binary.LittleEndian, v.servicesFrom)
	binary.Write(&buf, binary.BigEndian, v.ipFrom)
	binary.Write(&buf, binary.BigEndian, v.portFrom)
	binary.Write(&buf, binary.LittleEndian, v.nonce)

	userAgentBytes := []byte(v.userAgent)
	userAgentLen := encodeVariableLengthInt(uint64(len(userAgentBytes)))
	binary.Write(&buf, binary.LittleEndian, userAgentLen)
	binary.Write(&buf, binary.LittleEndian, userAgentBytes)

	binary.Write(&buf, binary.LittleEndian, v.startHeight)
	binary.Write(&buf, binary.LittleEndian, v.relay)

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

func (m message) Serialize() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, magic)

	var commandBytes [maxCommandLen]byte
	copy(commandBytes[:], m.command)
	binary.Write(&buf, binary.LittleEndian, commandBytes)

	payloadBytes := m.payload.Serialize()

	binary.Write(&buf, binary.LittleEndian, uint32(len(payloadBytes)))

	checksum := checksum(payloadBytes)
	binary.Write(&buf, binary.LittleEndian, checksum)

	binary.Write(&buf, binary.LittleEndian, m.payload.Serialize())

	return buf.Bytes()
}
