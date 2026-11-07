package importer

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mac-proxy/internal/engine"
)

func UpdateUsage(item *engine.Subscription, usage *engine.SubscriptionUsage) {
	previous := item.Usage
	item.Usage = usage
	if usage.Used == nil || usage.Total == nil || *usage.Total == 0 {
		item.UsageSamples = nil
		return
	}
	if previous != nil && previous.Used != nil && previous.Total != nil {
		if *previous.Total != *usage.Total || *previous.Used > *usage.Used {
			item.UsageSamples = nil
		} else if len(item.UsageSamples) == 0 {
			item.UsageSamples = append(item.UsageSamples, engine.UsageSample{
				Time: previous.UpdatedAt, Used: *previous.Used, Total: *previous.Total,
			})
		}
	}
	cutoff := usage.UpdatedAt - 8*24*3600
	for len(item.UsageSamples) > 0 && item.UsageSamples[0].Time < cutoff {
		item.UsageSamples = item.UsageSamples[1:]
	}
	last := len(item.UsageSamples) - 1
	if last < 0 || usage.UpdatedAt-item.UsageSamples[last].Time >= 3600 {
		item.UsageSamples = append(item.UsageSamples, engine.UsageSample{
			Time: usage.UpdatedAt, Used: *usage.Used, Total: *usage.Total,
		})
	}
}

func readUsage(header, body string) *engine.SubscriptionUsage {
	meter := engine.SubscriptionUsage{UpdatedAt: time.Now().Unix()}
	var upload, download *uint64
	for part := range strings.SplitSeq(header, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "upload":
			upload = &number
		case "download":
			download = &number
		case "total":
			meter.Total = &number
		case "expire":
			if number <= math.MaxInt64 {
				meter.ExpiresAt = int64(number)
			}
		}
	}
	meter.Used = sumUsage(upload, download)
	if meter.Used != nil || meter.Total != nil {
		return &meter
	}
	return readShadowrocketUsage(body, meter)
}

var shadowrocketUsage = regexp.MustCompile(`^STATUS=.*?↑\s*:\s*([0-9.]+\s*[A-Za-z]+).*?↓\s*:\s*([0-9.]+\s*[A-Za-z]+).*?TOT\s*:\s*([0-9.]+\s*[A-Za-z]+)`)
var shadowrocketExpiry = regexp.MustCompile(`Expires\s*:\s*(\d{4}-\d{1,2}-\d{1,2})`)

func readShadowrocketUsage(body string, meter engine.SubscriptionUsage) *engine.SubscriptionUsage {
	body = strings.TrimSpace(strings.TrimPrefix(body, "\ufeff"))
	if !strings.HasPrefix(body, "STATUS=") {
		decoded, err := decodeBase64(strings.Join(strings.Fields(body), ""))
		if err != nil {
			return nil
		}
		body = strings.TrimSpace(strings.TrimPrefix(string(decoded), "\ufeff"))
	}
	line, _, _ := strings.Cut(body, "\n")
	match := shadowrocketUsage.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	meter.Used = sumUsage(humanBytes(match[1]), humanBytes(match[2]))
	meter.Total = humanBytes(match[3])
	if expiry := shadowrocketExpiry.FindStringSubmatch(line); expiry != nil {
		if date, err := time.Parse("2006-1-2", expiry[1]); err == nil {
			meter.ExpiryDate = date.Format("2006-01-02")
		}
	}
	if meter.Used == nil && meter.Total == nil {
		return nil
	}
	return &meter
}

func sumUsage(upload, download *uint64) *uint64 {
	if upload == nil || download == nil || math.MaxUint64-*upload < *download {
		return nil
	}
	used := *upload + *download
	return &used
}

var quantity = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)$`)

func humanBytes(value string) *uint64 {
	match := quantity.FindStringSubmatch(value)
	if match == nil {
		return nil
	}
	number, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return nil
	}
	var factor float64
	switch strings.ToUpper(match[2]) {
	case "B":
		factor = 1
	case "KB", "KIB":
		factor = 1 << 10
	case "MB", "MIB":
		factor = 1 << 20
	case "GB", "GIB":
		factor = 1 << 30
	case "TB", "TIB":
		factor = 1 << 40
	default:
		return nil
	}
	bytes := number * factor
	if bytes >= float64(math.MaxUint64) {
		return nil
	}
	rounded := uint64(math.Round(bytes))
	return &rounded
}
