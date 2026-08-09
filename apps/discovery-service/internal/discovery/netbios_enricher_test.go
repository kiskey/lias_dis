package discovery

import (
	"encoding/binary"
	"testing"
)

func TestNodeStatusRequestUsesWildcardZeroPadding(t *testing.T) {
	request := buildNodeStatusRequest(0x1234)
	if request[13] != 'C' || request[14] != 'K' {
		t.Fatalf("wildcard was not encoded: %q", request[13:15])
	}
	for i := 15; i < 45; i++ {
		if request[i] != 'A' {
			t.Fatalf("wildcard padding byte %d was %q", i, request[i])
		}
	}
}

func TestParseNodeStatusResponseWithCompressedAnswer(t *testing.T) {
	const transactionID = 0x4321
	request := buildNodeStatusRequest(transactionID)
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], transactionID)
	binary.BigEndian.PutUint16(packet[2:4], 0x8500)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	packet = append(packet, request[12:]...)
	packet = append(packet, 0xc0, 0x0c)
	rr := make([]byte, 10)
	binary.BigEndian.PutUint16(rr[0:2], netBIOSNodeStatusType)
	binary.BigEndian.PutUint16(rr[2:4], netBIOSClassIN)
	rdata := make([]byte, 1+18+46)
	rdata[0] = 1
	copy(rdata[1:16], []byte("DESKTOP        "))
	rdata[16] = 0x00
	binary.BigEndian.PutUint16(rdata[17:19], 0x0000)
	binary.BigEndian.PutUint16(rr[8:10], uint16(len(rdata)))
	packet = append(packet, rr...)
	packet = append(packet, rdata...)
	names, err := parseNodeStatusResponse(packet, transactionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name != "DESKTOP" || names[0].Suffix != 0x00 {
		t.Fatalf("unexpected names: %+v", names)
	}
	if _, err := parseNodeStatusResponse(packet, transactionID+1); err == nil {
		t.Fatal("transaction mismatch accepted")
	}
}

func TestParseNodeStatusRejectsCompressionLoopAndTruncation(t *testing.T) {
	packet := make([]byte, 14)
	binary.BigEndian.PutUint16(packet[0:2], 1)
	binary.BigEndian.PutUint16(packet[2:4], 0x8500)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	packet[12], packet[13] = 0xc0, 0x0c
	if _, err := parseNodeStatusResponse(packet, 1); err == nil {
		t.Fatal("compression loop accepted")
	}
	if _, err := parseNodeStatusRDATA([]byte{2, 0}); err == nil {
		t.Fatal("truncated name table accepted")
	}
}
