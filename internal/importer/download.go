package importer

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Validators struct {
	Scope        string `json:"scope"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// DownloadError exposes only safe status and retry metadata to callers.
type DownloadError struct {
	Status     int
	RetryAfter time.Time
}

func (err *DownloadError) Error() string {
	if err.Status == http.StatusTooManyRequests {
		return "订阅服务器限流（HTTP 429），稍后可重试"
	}
	return fmt.Sprintf("订阅服务器返回 HTTP %d", err.Status)
}

type download struct {
	body        []byte
	usage       string
	validators  Validators
	notModified bool
}

var errInvalidRedirect = errors.New("订阅重定向不安全、循环或超过上限")

func fetch(ctx context.Context, source *url.URL, options Options) (download, error) {
	if source.User != nil || source.Hostname() == "" {
		return download{}, errors.New("订阅地址无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	applyValidators := func(request *http.Request) {
		request.Header.Del("If-None-Match")
		request.Header.Del("If-Modified-Since")
		if validatorScope(request.URL, options.Agent) == options.Validators.Scope {
			if options.Validators.ETag != "" {
				request.Header.Set("If-None-Match", options.Validators.ETag)
			}
			if options.Validators.LastModified != "" {
				request.Header.Set("If-Modified-Since", options.Validators.LastModified)
			}
		}
	}
	client := &http.Client{Transport: options.Transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 || next.URL.User != nil ||
			(next.URL.Scheme != "https" && (next.URL.Scheme != "http" || via[len(via)-1].URL.Scheme == "https")) {
			return errInvalidRedirect
		}
		// A validator belongs to the final URL and client format that
		// produced it, including when the source redirected there.
		for _, previous := range via {
			if next.URL.String() == previous.URL.String() {
				return errInvalidRedirect
			}
		}
		applyValidators(next)
		return nil
	}}
	var failure error
	for attempt := range 3 {
		request, err := http.NewRequestWithContext(ctx, "GET", source.String(), nil)
		if err != nil {
			return download{}, errors.New("订阅地址无效")
		}
		request.Header.Set("User-Agent", options.Agent)
		request.Header.Set("Accept-Encoding", "gzip")
		applyValidators(request)
		response, err := client.Do(request)
		retry := false
		switch {
		case ctx.Err() != nil:
			if response != nil {
				response.Body.Close()
			}
			return download{}, ctx.Err()
		case errors.Is(err, errInvalidRedirect):
			return download{}, errInvalidRedirect
		case err != nil:
			retry = retryTransport(err)
			failure = errors.New("无法下载订阅，请检查网络和链接")
		default:
			if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNotModified {
				return readDownload(response, options.Agent, options.Validators)
			}
			var retryAt time.Time
			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
				retryAt = parseRetryAfter(response.Header.Get("Retry-After"), time.Now())
			}
			if response.StatusCode == http.StatusTooManyRequests && retryAt.IsZero() {
				retryAt = time.Now().Add(time.Minute)
			}
			failure = &DownloadError{Status: response.StatusCode, RetryAfter: retryAt}
			// Allow short error bodies to drain for reuse without allocating.
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
			response.Body.Close()
			switch response.StatusCode {
			case http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway,
				http.StatusServiceUnavailable, http.StatusGatewayTimeout:
				retry = retryAt.IsZero()
			}
		}
		if !retry || attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return download{}, ctx.Err()
		case <-timer.C:
		}
	}
	return download{}, failure
}

func retryTransport(err error) bool {
	var networkError net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.As(err, &networkError) && networkError.Timeout()
}

func parseRetryAfter(value string, now time.Time) time.Time {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		// Keep malformed or extreme hints from overflowing a duration.
		const maxSeconds = uint64(30 * 24 * 3600)
		return now.Add(time.Duration(min(seconds, maxSeconds)) * time.Second)
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at
	}
	return time.Time{}
}

func validatorScope(source *url.URL, agent string) string {
	sum := sha256.Sum256([]byte(source.String() + "\x00" + agent))
	return hex.EncodeToString(sum[:])
}

func readDownload(response *http.Response, agent string, previous Validators) (download, error) {
	defer response.Body.Close()
	request := response.Request
	if request == nil || request.URL == nil {
		return download{}, errors.New("订阅服务器应答缺少请求地址")
	}
	out := download{validators: Validators{Scope: validatorScope(request.URL, agent)}}
	if etag := response.Header.Get("ETag"); len(etag) <= 1024 {
		out.validators.ETag = etag
	}
	if modified := response.Header.Get("Last-Modified"); modified != "" {
		if _, err := http.ParseTime(modified); err == nil {
			out.validators.LastModified = modified
		}
	}
	if response.StatusCode == http.StatusNotModified {
		if out.validators.Scope != previous.Scope ||
			(request.Header.Get("If-None-Match") == "" && request.Header.Get("If-Modified-Since") == "") {
			return download{}, errors.New("订阅返回 HTTP 304，但没有对应的本地缓存")
		}
		if out.validators.ETag == "" {
			out.validators.ETag = previous.ETag
		}
		if out.validators.LastModified == "" {
			out.validators.LastModified = previous.LastModified
		}
		out.notModified = true
		return out, nil
	}
	var body io.Reader = response.Body
	compressed := false
	switch encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding"))); encoding {
	case "", "identity":
	case "gzip":
		reader, err := gzip.NewReader(io.LimitReader(response.Body, 2*MaxSize))
		if err != nil {
			return download{}, errors.New("压缩订阅响应不完整或损坏")
		}
		defer reader.Close()
		body, compressed = reader, true
	default:
		return download{}, errors.New("订阅使用了不支持的压缩格式")
	}
	data, err := readBounded(body)
	if err != nil {
		if compressed && !errors.Is(err, errImportTooLarge) {
			return download{}, errors.New("压缩订阅响应不完整或损坏")
		}
		return download{}, err
	}
	out.body, out.usage = data, response.Header.Get("Subscription-Userinfo")
	return out, nil
}

func isHTMLDocument(text string) bool {
	prefix := strings.ToLower(text[:min(len(text), 24)])
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") ||
		strings.HasPrefix(prefix, "<head") || strings.HasPrefix(prefix, "<body")
}
