package engine

import (
	"crypto/sha256"
	"encoding/hex"
)

func (sub Subscription) Key() string {
	if sub.ID != "" {
		return sub.ID
	}
	sum := sha256.Sum256([]byte(sub.URL))
	return hex.EncodeToString(sum[:])
}

type SubscriptionUsage struct {
	Used       *uint64 `json:"used,omitempty"`
	Total      *uint64 `json:"total,omitempty"`
	ExpiresAt  int64   `json:"expiresAt,omitempty"`
	ExpiryDate string  `json:"expiryDate,omitempty"`
	UpdatedAt  int64   `json:"updatedAt"`
}

type UsageSample struct {
	Time  int64  `json:"time"`
	Used  uint64 `json:"used"`
	Total uint64 `json:"total"`
}
