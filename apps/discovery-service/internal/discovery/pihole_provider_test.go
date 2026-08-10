package discovery

import "testing"

func TestParsePiholeTopClientsV6(t *testing.T) {
	clients, err := parsePiholeClients("/api/stats/top_clients?count=100", []byte(`{
        "clients": [{"ip":"192.168.1.10","name":"phone","count":42}],
        "total_queries": 42
    }`))
	if err != nil {
		t.Fatalf("parse top clients: %v", err)
	}
	if len(clients) != 1 || clients[0].IP != "192.168.1.10" || clients[0].Name != "phone" {
		t.Fatalf("unexpected clients: %+v", clients)
	}
}

func TestParsePiholeNetworkDevicesV6(t *testing.T) {
	clients, err := parsePiholeClients("/api/network/devices", []byte(`{
        "devices": [{
            "hwaddr":"aa:bb:cc:dd:ee:ff",
            "macVendor":"Example Vendor",
            "ips":[{"ip":"192.168.1.20","name":"tablet","lastSeen":123}]
        }]
    }`))
	if err != nil {
		t.Fatalf("parse network devices: %v", err)
	}
	if len(clients) != 1 || clients[0].Mac != "aa:bb:cc:dd:ee:ff" || clients[0].Vendor != "Example Vendor" {
		t.Fatalf("unexpected clients: %+v", clients)
	}
}
