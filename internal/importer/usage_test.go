package importer

import (
	"encoding/base64"
	"testing"
)

func TestShadowrocketMeterFromStatusLine(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("STATUS=🚀↑:1.5GB,↓:512MB,TOT:10GB💡Expires:2027-1-2\r\n"))
	meter := readUsage("", body)
	if meter == nil || meter.Used == nil || *meter.Used != 2<<30 ||
		meter.Total == nil || *meter.Total != 10<<30 || meter.ExpiryDate != "2027-01-02" {
		t.Fatalf("unexpected meter: %+v", meter)
	}
}
