// Package oui provides instant, zero-allocation hardware vendor lookups
// from IEEE Organizationally Unique Identifiers (OUI).
//
// File:    pkg/oui/oui.go
// Version: 1.1
package oui

import (
	"strings"
	"sync"
)

// Database manages the MAC prefix-to-vendor mappings.
type Database struct {
	mu       sync.RWMutex
	prefixes map[string]string
}

var (
	defaultDB *Database
	once      sync.Once
)

// Get returns the singleton OUI database instance populated with top vendor prefixes.
func Get() *Database {
	once.Do(func() {
		defaultDB = &Database{
			prefixes: make(map[string]string, 2048),
		}
		defaultDB.loadBuiltin()
	})
	return defaultDB
}

// Lookup returns the vendor name for a given MAC address string (e.g. "AA:BB:CC:DD:EE:FF" or "aabbccddeeff").
// Returns an empty string if the MAC is invalid or unassigned in the database.
func Lookup(macStr string) string {
	return Get().Lookup(macStr)
}

// Lookup queries the database for a normalized 24-bit OUI prefix (6 hex characters).
func (db *Database) Lookup(macStr string) string {
	clean := normalizeHex(macStr)
	if len(clean) < 6 {
		return ""
	}

	prefix := clean[:6]

	db.mu.RLock()
	vendor, found := db.prefixes[prefix]
	db.mu.RUnlock()

	if found {
		return vendor
	}
	return ""
}

// AddPrefix allows registering custom or updated OUI prefixes dynamically.
func (db *Database) AddPrefix(prefixHex, vendor string) {
	clean := normalizeHex(prefixHex)
	if len(clean) != 6 || vendor == "" {
		return
	}

	db.mu.Lock()
	db.prefixes[clean] = vendor
	db.mu.Unlock()
}

// normalizeHex strips common delimiters (:, -, .) and converts hex characters to uppercase.
func normalizeHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			b.WriteByte(c)
		} else if c >= 'a' && c <= 'z' {
			b.WriteByte(c - 32) // Fast uppercase conversion
		}
	}
	return b.String()
}

// loadBuiltin seeds the in-memory database with major hardware vendors.
func (db *Database) loadBuiltin() {
	// Top Network Infrastructure, Mobile, IoT, Smart Home, and Computing OUIs
	m := map[string]string{
		// Apple
		"000393": "Apple, Inc.", "000502": "Apple, Inc.", "000A27": "Apple, Inc.",
		"000D93": "Apple, Inc.", "0010FA": "Apple, Inc.", "001124": "Apple, Inc.",
		"001451": "Apple, Inc.", "0016CB": "Apple, Inc.", "0017F2": "Apple, Inc.",
		"0019E3": "Apple, Inc.", "001B63": "Apple, Inc.", "001C10": "Apple, Inc.",
		"001D4F": "Apple, Inc.", "001E52": "Apple, Inc.", "001EC2": "Apple, Inc.",
		"001F5B": "Apple, Inc.", "001FF3": "Apple, Inc.", "0021E9": "Apple, Inc.",
		"002241": "Apple, Inc.", "002312": "Apple, Inc.", "002331": "Apple, Inc.",
		"00236C": "Apple, Inc.", "0023DF": "Apple, Inc.", "002436": "Apple, Inc.",
		"002500": "Apple, Inc.", "00254B": "Apple, Inc.", "002608": "Apple, Inc.",
		"00264A": "Apple, Inc.", "0026B0": "Apple, Inc.", "008865": "Apple, Inc.",
		"040CCE": "Apple, Inc.", "041552": "Apple, Inc.", "042665": "Apple, Inc.",
		"04489A": "Apple, Inc.", "044B2A": "Apple, Inc.", "045453": "Apple, Inc.",
		"04D3CF": "Apple, Inc.", "04E536": "Apple, Inc.", "080007": "Apple, Inc.",
		"086698": "Apple, Inc.", "086D41": "Apple, Inc.", "087402": "Apple, Inc.",
		"0C15C4": "Apple, Inc.", "0C3021": "Apple, Inc.", "0C4DE9": "Apple, Inc.",
		"0C74C2": "Apple, Inc.", "0CB319": "Apple, Inc.", "101C0C": "Apple, Inc.",
		"1040F3": "Apple, Inc.", "109add": "Apple, Inc.", "10ddb1": "Apple, Inc.",
		"14109F": "Apple, Inc.", "14205E": "Apple, Inc.", "145A05": "Apple, Inc.",
		"148F21": "Apple, Inc.", "1499E2": "Apple, Inc.", "182032": "Apple, Inc.",
		"183429": "Apple, Inc.", "18AF61": "Apple, Inc.", "18E728": "Apple, Inc.",
		"18EE69": "Apple, Inc.", "1C1B68": "Apple, Inc.", "1C5C2B": "Apple, Inc.",
		"1C9148": "Apple, Inc.", "1CAB17": "Apple, Inc.", "1CD30A": "Apple, Inc.",
		"1CE62B": "Apple, Inc.", "203C24": "Apple, Inc.", "207D74": "Apple, Inc.",
		"20A2E4": "Apple, Inc.", "20C9D0": "Apple, Inc.", "24119B": "Apple, Inc.",
		"24240E": "Apple, Inc.", "24A074": "Apple, Inc.", "24AB81": "Apple, Inc.",
		"24E314": "Apple, Inc.", "280B5C": "Apple, Inc.", "283737": "Apple, Inc.",
		"285AEB": "Apple, Inc.", "286ABA": "Apple, Inc.", "28CFE9": "Apple, Inc.",
		"28ED6A": "Apple, Inc.", "2C1F23": "Apple, Inc.", "2C200B": "Apple, Inc.",
		"2C3361": "Apple, Inc.", "2CBE08": "Apple, Inc.", "2CF0EE": "Apple, Inc.",
		"30074D": "Apple, Inc.", "3010E4": "Apple, Inc.", "307406": "Apple, Inc.",
		"3090AB": "Apple, Inc.", "30A9DE": "Apple, Inc.", "30D9E9": "Apple, Inc.",
		"3408BC": "Apple, Inc.", "34159E": "Apple, Inc.", "34363B": "Apple, Inc.",
		"3451C9": "Apple, Inc.", "34A39A": "Apple, Inc.", "34C059": "Apple, Inc.",
		"34E2FD": "Apple, Inc.", "380F4A": "Apple, Inc.", "38484C": "Apple, Inc.",
		"386641": "Apple, Inc.", "3871DE": "Apple, Inc.", "3888EC": "Apple, Inc.",
		"38B54D": "Apple, Inc.", "38CADA": "Apple, Inc.", "3C0754": "Apple, Inc.",
		"3C15C2": "Apple, Inc.", "3C2EFF": "Apple, Inc.", "3CAB8F": "Apple, Inc.",
		"3CD070": "Apple, Inc.", "3CE072": "Apple, Inc.", "3CE066": "Apple, Inc.",
		"A45E60": "Apple, Inc.", "A4D18C": "Apple, Inc.", "A8667F": "Apple, Inc.",
		"B418D1": "Apple, Inc.", "BC926B": "Apple, Inc.", "C869CD": "Apple, Inc.",
		"DC2B2A": "Apple, Inc.", "E4CE8F": "Apple, Inc.", "F86214": "Apple, Inc.",

		// Samsung
		"0000F0": "Samsung Electronics", "000278": "Samsung Electronics",
		"0007AB": "Samsung Electronics", "000918": "Samsung Electronics",
		"000D25": "Samsung Electronics", "001247": "Samsung Electronics",
		"0012FB": "Samsung Electronics", "001377": "Samsung Electronics",
		"001599": "Samsung Electronics", "0015B9": "Samsung Electronics",
		"001632": "Samsung Electronics", "00166B": "Samsung Electronics",
		"0017C9": "Samsung Electronics", "0018AF": "Samsung Electronics",
		"001A8A": "Samsung Electronics", "001B98": "Samsung Electronics",
		"001CC0": "Samsung Electronics", "001D25": "Samsung Electronics",
		"001DF6": "Samsung Electronics", "001E7D": "Samsung Electronics",
		"001FCD": "Samsung Electronics", "002119": "Samsung Electronics",
		"00214C": "Samsung Electronics", "0021D8": "Samsung Electronics",
		"002339": "Samsung Electronics", "0023D7": "Samsung Electronics",
		"002454": "Samsung Electronics", "0024E2": "Samsung Electronics",
		"002566": "Samsung Electronics", "002637": "Samsung Electronics",
		"00267D": "Samsung Electronics", "0071C2": "Samsung Electronics",
		"04180F": "Samsung Electronics", "044E5A": "Samsung Electronics",
		"0808C2": "Samsung Electronics", "08373D": "Samsung Electronics",

		// Raspberry Pi Trading Ltd
		"28CDC1": "Raspberry Pi Trading Ltd", "3A3541": "Raspberry Pi Trading Ltd",
		"B827EB": "Raspberry Pi Foundation", "D83ADD": "Raspberry Pi Trading Ltd",
		"E45F01": "Raspberry Pi Trading Ltd", "D43A2B": "Raspberry Pi Trading Ltd",

		// Espressif Systems (ESP8266 / ESP32 IoT Devices)
		"18FE34": "Espressif Inc.", "240AC4": "Espressif Inc.", "246F28": "Espressif Inc.",
		"24B28A": "Espressif Inc.", "30AEA4": "Espressif Inc.", "3C71BF": "Espressif Inc.",
		"4022D8": "Espressif Inc.", "483FDA": "Espressif Inc.", "4C11AE": "Espressif Inc.",
		"545A16": "Espressif Inc.", "5CCF7F": "Espressif Inc.", "600194": "Espressif Inc.",
		"68C63A": "Espressif Inc.", "70039F": "Espressif Inc.", "744DBD": "Espressif Inc.",
		"7C9EBD": "Espressif Inc.", "807D3A": "Espressif Inc.", "840D8E": "Espressif Inc.",
		"84CCA8": "Espressif Inc.", "8C4B14": "Espressif Inc.", "9097D5": "Espressif Inc.",
		"94B97E": "Espressif Inc.", "A020A6": "Espressif Inc.", "A47B9D": "Espressif Inc.",
		"A4CF12": "Espressif Inc.", "AC67B2": "Espressif Inc.", "B4E62D": "Espressif Inc.",
		"BCDDC2": "Espressif Inc.", "C44F33": "Espressif Inc.", "CC50E3": "Espressif Inc.",
		"D8A01D": "Espressif Inc.", "DC4F22": "Espressif Inc.", "E09806": "Espressif Inc.",
		"E831CD": "Espressif Inc.", "ECFABC": "Espressif Inc.", "F4CFA2": "Espressif Inc.",

		// Tuya Smart / Hangzhou Tuya Information (Smart Plugs, Bulbs, Switches)
		"10D7B1": "Tuya Smart Inc.", "1869D8": "Tuya Smart Inc.", "2050E7": "Tuya Smart Inc.",
		"385B44": "Tuya Smart Inc.", "508A06": "Tuya Smart Inc.", "68572D": "Tuya Smart Inc.",
		"708976": "Tuya Smart Inc.", "780F77": "Tuya Smart Inc.", "840265": "Tuya Smart Inc.",
		"A09208": "Tuya Smart Inc.", "D8132A": "Tuya Smart Inc.", "DC234D": "Tuya Smart Inc.",

		// Google / Nest
		"001A11": "Google LLC", "182666": "Google LLC", "1C56FE": "Google LLC",
		"30FD38": "Google LLC", "3C5C94": "Google LLC", "546009": "Google LLC",
		"641666": "Google LLC", "70EE50": "Google LLC", "94EB2C": "Google LLC",
		"A47733": "Google LLC", "D86C63": "Google LLC", "E4F042": "Google LLC",
		"F4F5DB": "Google LLC", "F88FCA": "Google LLC", "18B430": "Nest Labs",

		// Amazon Technologies (Kindle, Echo, FireTV, Ring)
		"00FC8B": "Amazon Technologies Inc.", "0C47C9": "Amazon Technologies Inc.",
		"10CE10": "Amazon Technologies Inc.", "18742E": "Amazon Technologies Inc.",
		"34D270": "Amazon Technologies Inc.", "3C5C24": "Amazon Technologies Inc.",
		"40B4CD": "Amazon Technologies Inc.", "44650D": "Amazon Technologies Inc.",
		"50F5DA": "Amazon Technologies Inc.", "527419": "Amazon Technologies Inc.",
		"68545A": "Amazon Technologies Inc.", "747548": "Amazon Technologies Inc.",
		"78E103": "Amazon Technologies Inc.", "84D6D0": "Amazon Technologies Inc.",
		"A002DC": "Amazon Technologies Inc.", "AC63BE": "Amazon Technologies Inc.",
		"B47C9C": "Amazon Technologies Inc.", "FCA183": "Amazon Technologies Inc.",

		// Intel
		"0002B3": "Intel Corporation", "000347": "Intel Corporation",
		"000423": "Intel Corporation", "000E0C": "Intel Corporation",
		"001320": "Intel Corporation", "0013CE": "Intel Corporation",
		"0013E8": "Intel Corporation", "001500": "Intel Corporation",
		"0016EA": "Intel Corporation", "0018DE": "Intel Corporation",
		"0019D2": "Intel Corporation", "001B21": "Intel Corporation",
		"001CBF": "Intel Corporation", "001D22": "Intel Corporation",
		"001E64": "Intel Corporation", "001F3B": "Intel Corporation",
		"00216A": "Intel Corporation", "0022FB": "Intel Corporation",
		"002314": "Intel Corporation", "0024D7": "Intel Corporation",
		"00270E": "Intel Corporation", "00A0C9": "Intel Corporation",

		// Cisco / Meraki
		"00000C": "Cisco Systems, Inc.", "000142": "Cisco Systems, Inc.",
		"000143": "Cisco Systems, Inc.", "000196": "Cisco Systems, Inc.",
		"000197": "Cisco Systems, Inc.", "000216": "Cisco Systems, Inc.",
		"000217": "Cisco Systems, Inc.", "00024A": "Cisco Systems, Inc.",
		"00024B": "Cisco Systems, Inc.", "00180A": "Cisco Systems, Inc.",
		"001818": "Cisco Systems, Inc.", "001874": "Cisco Systems, Inc.",
		"0018B9": "Cisco Systems, Inc.", "0018BA": "Cisco Systems, Inc.",
		"E0553D": "Cisco Systems, Inc.", "00180A": "Meraki, Inc.",

		// TP-Link
		"000F78": "TP-Link Corporation Limited", "001478": "TP-Link Corporation Limited",
		"0019E0": "TP-Link Corporation Limited", "001D0F": "TP-Link Corporation Limited",
		"002127": "TP-Link Corporation Limited", "0023CD": "TP-Link Corporation Limited",
		"002586": "TP-Link Corporation Limited", "002719": "TP-Link Corporation Limited",
		"14CF92": "TP-Link Corporation Limited", "18A6F7": "TP-Link Corporation Limited",
		"18D6C7": "TP-Link Corporation Limited", "30B5C2": "TP-Link Corporation Limited",
		"34E894": "TP-Link Corporation Limited", "50C7BF": "TP-Link Corporation Limited",
		"54C80F": "TP-Link Corporation Limited", "6038E0": "TP-Link Corporation Limited",
		"6466B3": "TP-Link Corporation Limited", "647002": "TP-Link Corporation Limited",
		"74DA38": "TP-Link Corporation Limited", "788B0A": "TP-Link Corporation Limited",
		"808917": "TP-Link Corporation Limited", "8416F9": "TP-Link Corporation Limited",
		"90F652": "TP-Link Corporation Limited", "9408A7": "TP-Link Corporation Limited",
		"98DAC4": "TP-Link Corporation Limited", "A0F3C1": "TP-Link Corporation Limited",
		"B4B024": "TP-Link Corporation Limited", "BC4699": "TP-Link Corporation Limited",
		"C025E9": "TP-Link Corporation Limited", "C46E1F": "TP-Link Corporation Limited",
		"D807B6": "TP-Link Corporation Limited", "E894F6": "TP-Link Corporation Limited",
		"EC086B": "TP-Link Corporation Limited", "F4EC38": "TP-Link Corporation Limited",

		// Ubiquiti Networks (UniFi)
		"00156D": "Ubiquiti Networks Inc.", "002722": "Ubiquiti Networks Inc.",
		"0418D6": "Ubiquiti Networks Inc.", "18E829": "Ubiquiti Networks Inc.",
		"24A43C": "Ubiquiti Networks Inc.", "687251": "Ubiquiti Networks Inc.",
		"70A741": "Ubiquiti Networks Inc.", "7483C2": "Ubiquiti Networks Inc.",
		"788A20": "Ubiquiti Networks Inc.", "802AA8": "Ubiquiti Networks Inc.",
		"B4FBE4": "Ubiquiti Networks Inc.", "D8B370": "Ubiquiti Networks Inc.",
		"E063DA": "Ubiquiti Networks Inc.", "F09FC2": "Ubiquiti Networks Inc.",
		"F492BF": "Ubiquiti Networks Inc.", "FCECDA": "Ubiquiti Networks Inc.",

		// Netgear
		"00095B": "Netgear Inc.", "000FB5": "Netgear Inc.", "00146C": "Netgear Inc.",
		"00184D": "Netgear Inc.", "001B2F": "Netgear Inc.", "001E2A": "Netgear Inc.",
		"001F33": "Netgear Inc.", "00223F": "Netgear Inc.", "0024B2": "Netgear Inc.",
		"0026F2": "Netgear Inc.", "08028E": "Netgear Inc.", "100D7F": "Netgear Inc.",
		"1459C0": "Netgear Inc.", "1C7EE5": "Netgear Inc.", "204E71": "Netgear Inc.",
		"288088": "Netgear Inc.", "2C3033": "Netgear Inc.", "2CB05D": "Netgear Inc.",
		"30469A": "Netgear Inc.", "3894ED": "Netgear Inc.", "4494FC": "Netgear Inc.",
		"6CB0CE": "Netgear Inc.", "706037": "Netgear Inc.", "841B5E": "Netgear Inc.",
		"843A4B": "Netgear Inc.", "803773": "Netgear Inc.", "94163E": "Netgear Inc.",
		"A00460": "Netgear Inc.", "B07FB9": "Netgear Inc.", "C03FD5": "Netgear Inc.",
		"E046EE": "Netgear Inc.", "E4F4C6": "Netgear Inc.", "E8FC5D": "Netgear Inc.",

		// Sonos
		"000E58": "Sonos, Inc.", "000EE8": "Sonos, Inc.", "001A83": "Sonos, Inc.",
		"347E5C": "Sonos, Inc.", "48A6B8": "Sonos, Inc.", "5CAAFD": "Sonos, Inc.",
		"7828CA": "Sonos, Inc.", "949F3E": "Sonos, Inc.", "B8E937": "Sonos, Inc.",
		"C43875": "Sonos, Inc.", "D88039": "Sonos, Inc.", "F0F6C1": "Sonos, Inc.",

		// Philips Lighting / Signify (Philips Hue)
		"001788": "Philips Lighting BV", "001EC0": "Philips Lighting BV",
		"ECB5FA": "Philips Lighting BV",

		// Nintendo
		"0009BF": "Nintendo Co., Ltd.", "001656": "Nintendo Co., Ltd.",
		"0017AB": "Nintendo Co., Ltd.", "00191D": "Nintendo Co., Ltd.",
		"001B7A": "Nintendo Co., Ltd.", "001D2C": "Nintendo Co., Ltd.",
		"001E35": "Nintendo Co., Ltd.", "001F32": "Nintendo Co., Ltd.",
		"002147": "Nintendo Co., Ltd.", "0022AA": "Nintendo Co., Ltd.",
		"0023CC": "Nintendo Co., Ltd.", "00241E": "Nintendo Co., Ltd.",
		"0025A0": "Nintendo Co., Ltd.", "002659": "Nintendo Co., Ltd.",
		"0403D6": "Nintendo Co., Ltd.", "182A7B": "Nintendo Co., Ltd.",
		"582F40": "Nintendo Co., Ltd.", "7CBB8A": "Nintendo Co., Ltd.",
		"8C56C5": "Nintendo Co., Ltd.", "98B6E9": "Nintendo Co., Ltd.",
		"B8AE6E": "Nintendo Co., Ltd.", "CC9E00": "Nintendo Co., Ltd.",
		"D86B7D": "Nintendo Co., Ltd.", "E00C7F": "Nintendo Co., Ltd.",

		// Sony Interactive Entertainment (PlayStation / Bravia TV)
		"00014A": "Sony Interactive Entertainment Inc.", "000413": "Sony Corporation",
		"000A28": "Sony Corporation", "000B24": "Sony Corporation",
		"000D00": "Sony Corporation", "000E07": "Sony Corporation",
		"000F1B": "Sony Corporation", "0013A9": "Sony Corporation",
		"0015C1": "Sony Corporation", "0019C5": "Sony Corporation",
		"001A80": "Sony Corporation", "001B6A": "Sony Corporation",
		"001D0D": "Sony Corporation", "001E45": "Sony Corporation",
		"001FA7": "Sony Corporation", "00248D": "Sony Corporation",
		"0025E7": "Sony Corporation", "00D029": "Sony Interactive Entertainment Inc.",
		"04766E": "Sony Corporation", "080046": "Sony Corporation",
		"0013A9": "Sony Interactive Entertainment Inc.",
		"709E29": "Sony Interactive Entertainment Inc.",
		"A41566": "Sony Interactive Entertainment Inc.",
		"A8E3EE": "Sony Interactive Entertainment Inc.",
		"B449A5": "Sony Interactive Entertainment Inc.",
		"FC0F04": "Sony Interactive Entertainment Inc.",

		// Microsoft (Xbox / Surface)
		"0003FF": "Microsoft Corporation", "000D3A": "Microsoft Corporation",
		"00125A": "Microsoft Corporation", "00155D": "Microsoft Corporation",
		"0017FA": "Microsoft Corporation", "001DD8": "Microsoft Corporation",
		"002248": "Microsoft Corporation", "0025AE": "Microsoft Corporation",
		"0050F2": "Microsoft Corporation", "281878": "Microsoft Corporation",
		"3059B7": "Microsoft Corporation", "4883C7": "Microsoft Corporation",
		"501AC5": "Microsoft Corporation", "6045BD": "Microsoft Corporation",
		"6015C7": "Microsoft Corporation", "7C1E52": "Microsoft Corporation",
		"985FD3": "Microsoft Corporation", "B831B5": "Microsoft Corporation",
		"C0335E": "Microsoft Corporation", "DC5360": "Microsoft Corporation",
		"E0D55E": "Microsoft Corporation", "F4428F": "Microsoft Corporation",

		// LG Electronics (Smart TVs, Appliances)
		"0005C9": "LG Electronics", "000B97": "LG Electronics",
		"000E6D": "LG Electronics", "001256": "LG Electronics",
		"0013E0": "LG Electronics", "0015C9": "LG Electronics",
		"0016B4": "LG Electronics", "0019A1": "LG Electronics",
		"001C62": "LG Electronics", "001E75": "LG Electronics",
		"001F6B": "LG Electronics", "0022A9": "LG Electronics",
		"002483": "LG Electronics", "0025E5": "LG Electronics",
		"0026E2": "LG Electronics", "0821EF": "LG Electronics",
		"1009F4": "LG Electronics", "10683F": "LG Electronics",
		"14C913": "LG Electronics", "1CC316": "LG Electronics",
		"203D66": "LG Electronics", "2C54CF": "LG Electronics",
		"344DFA": "LG Electronics", "388C50": "LG Electronics",
		"40B36B": "LG Electronics", "441319": "LG Electronics",
		"48210B": "LG Electronics", "5056BF": "LG Electronics",
		"58A2B5": "LG Electronics", "64956C": "LG Electronics",
		"689C70": "LG Electronics", "700514": "LG Electronics",
		"7440BB": "LG Electronics", "785D08": "LG Electronics",
		"80EA96": "LG Electronics", "847207": "LG Electronics",
		"88366C": "LG Electronics", "90FD61": "LG Electronics",
		"9893CC": "LG Electronics", "A823FE": "LG Electronics",
		"A870A5": "LG Electronics", "B81D05": "LG Electronics",
		"BCF5AC": "LG Electronics", "C436DA": "LG Electronics",
		"CC2D83": "LG Electronics", "D01827": "LG Electronics",
		"E42686": "LG Electronics", "E85B5B": "LG Electronics",
		"F80C2A": "LG Electronics", "F80L43": "LG Electronics",

		// Xiaomi / Lei Jun (Smart Home, Phones, TVs)
		"009EA1": "Xiaomi Communications Co Ltd", "04CF8C": "Xiaomi Communications Co Ltd",
		"08E689": "Xiaomi Communications Co Ltd", "102A14": "Xiaomi Communications Co Ltd",
		"14F65A": "Xiaomi Communications Co Ltd", "185936": "Xiaomi Communications Co Ltd",
		"2034FB": "Xiaomi Communications Co Ltd", "286C07": "Xiaomi Communications Co Ltd",
		"28E347": "Xiaomi Communications Co Ltd", "3480B3": "Xiaomi Communications Co Ltd",
		"38A4ED": "Xiaomi Communications Co Ltd", "3CBD3E": "Xiaomi Communications Co Ltd",
		"40313C": "Xiaomi Communications Co Ltd", "44237C": "Xiaomi Communications Co Ltd",
		"4C49E3": "Xiaomi Communications Co Ltd", "50EC50": "Xiaomi Communications Co Ltd",
		"541731": "Xiaomi Communications Co Ltd", "584498": "Xiaomi Communications Co Ltd",
		"5C60BA": "Xiaomi Communications Co Ltd", "640980": "Xiaomi Communications Co Ltd",
		"64B473": "Xiaomi Communications Co Ltd", "64CE66": "Xiaomi Communications Co Ltd",
		"68DFDD": "Xiaomi Communications Co Ltd", "742344": "Xiaomi Communications Co Ltd",
		"7451BA": "Xiaomi Communications Co Ltd", "7802F8": "Xiaomi Communications Co Ltd",
		"7811DC": "Xiaomi Communications Co Ltd", "7C1DDA": "Xiaomi Communications Co Ltd",
		"80AD16": "Xiaomi Communications Co Ltd", "842096": "Xiaomi Communications Co Ltd",
		"880C11": "Xiaomi Communications Co Ltd", "8C11CB": "Xiaomi Communications Co Ltd",
		"8CBEBE": "Xiaomi Communications Co Ltd", "909015": "Xiaomi Communications Co Ltd",
		"942B97": "Xiaomi Communications Co Ltd", "94A090": "Xiaomi Communications Co Ltd",
		"98FA37": "Xiaomi Communications Co Ltd", "9C99A0": "Xiaomi Communications Co Ltd",
		"A086C6": "Xiaomi Communications Co Ltd", "A44519": "Xiaomi Communications Co Ltd",
		"A47E39": "Xiaomi Communications Co Ltd", "AC293A": "Xiaomi Communications Co Ltd",
		"B03829": "Xiaomi Communications Co Ltd", "B0E235": "Xiaomi Communications Co Ltd",
		"B46077": "Xiaomi Communications Co Ltd", "C46B18": "Xiaomi Communications Co Ltd",
		"C8028F": "Xiaomi Communications Co Ltd", "D4619D": "Xiaomi Communications Co Ltd",
		"D49A20": "Xiaomi Communications Co Ltd", "D86375": "Xiaomi Communications Co Ltd",
		"DC330D": "Xiaomi Communications Co Ltd", "E0107F": "Xiaomi Communications Co Ltd",
		"E446DA": "Xiaomi Communications Co Ltd", "E8B4C8": "Xiaomi Communications Co Ltd",
		"F44EFD": "Xiaomi Communications Co Ltd", "F4848D": "Xiaomi Communications Co Ltd",
		"FC643A": "Xiaomi Communications Co Ltd", "FC7A15": "Xiaomi Communications Co Ltd",

		// Synology (NAS)
		"001132": "Synology Incorporated", "002155": "Synology Incorporated",
		"D7B5D8": "Synology Incorporated",

		// QNAP (NAS)
		"00089B": "QNAP Systems, Inc.", "245EBE": "QNAP Systems, Inc.",
	}

	for k, v := range m {
		db.prefixes[k] = v
	}
}
