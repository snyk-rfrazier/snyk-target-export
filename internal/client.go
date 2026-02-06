// Package internal provides the Snyk API client, rate limiting, and retry
// logic for the snyk-refresh CLI.
package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// GetSnykAPIBaseURL returns the Snyk API base URL from environment or default.
// Priority: SNYK_API > SNYK_API_URL > default (https://api.snyk.io)
func GetSnykAPIBaseURL() string {
	if u := os.Getenv("SNYK_API"); u != "" {
		return strings.TrimSuffix(u, "/")
	}
	if u := os.Getenv("SNYK_API_URL"); u != "" {
		return strings.TrimSuffix(u, "/")
	}
	return "https://api.snyk.io"
}

// GetSnykToken returns the Snyk API token from environment variables.
func GetSnykToken() (string, error) {
	if t := os.Getenv("SNYK_TOKEN"); t != "" {
		return t, nil
	}
	if t := os.Getenv("SNYK_API_TOKEN"); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("SNYK_TOKEN or SNYK_API_TOKEN environment variable not set")
}

// NewHTTPClient returns an *http.Client with sensible defaults.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

// RetryConfig holds retry configuration.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig returns sensible defaults for Snyk API.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
	}
}

// isRetryableStatus returns true if the HTTP status code is retryable.
func isRetryableStatus(code int) bool {
	switch code {
	case 408, 429, 500, 502, 503, 504, 530:
		return true
	default:
		return false
	}
}

// getRetryAfter extracts the Retry-After header value in seconds.
func getRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		return 0
	}
	if secs, err := strconv.Atoi(ra); err == nil {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// calculateBackoff returns the backoff duration for the given attempt.
func calculateBackoff(attempt int, cfg RetryConfig) time.Duration {
	backoff := float64(cfg.InitialBackoff)
	for i := 0; i < attempt; i++ {
		backoff *= cfg.BackoffFactor
	}
	if backoff > float64(cfg.MaxBackoff) {
		backoff = float64(cfg.MaxBackoff)
	}
	return time.Duration(backoff)
}

// rateLimiter is a simple token-bucket rate limiter using a time.Ticker.
// It ensures at most ~requestsPerSecond sustained throughput.
type rateLimiter struct {
	ticker *time.Ticker
}

var globalLimiter *rateLimiter

func initRateLimiter() {
	if globalLimiter == nil {
		// ~2 requests per second (500ms between requests)
		globalLimiter = &rateLimiter{
			ticker: time.NewTicker(500 * time.Millisecond),
		}
	}
}

func (rl *rateLimiter) wait(ctx context.Context) error {
	select {
	case <-rl.ticker.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DoWithRetry performs an HTTP request with rate limiting and automatic retries.
// It handles 429 (rate limit) and 5xx (server error) responses with exponential backoff.
func DoWithRetry(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	initRateLimiter()
	cfg := DefaultRetryConfig()

	// Store original body for retries
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("read request body: %w", err)
		}
		req.Body.Close()
	}

	var lastErr error
	var lastResp *http.Response
	var lastBody []byte

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		// Rate limit
		if err := globalLimiter.wait(ctx); err != nil {
			return nil, nil, fmt.Errorf("rate limiter: %w", err)
		}

		// Clone request with fresh body
		reqClone, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("clone request: %w", err)
		}
		for k, v := range req.Header {
			reqClone.Header[k] = v
		}
		if bodyBytes != nil {
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.ContentLength = int64(len(bodyBytes))
		}

		resp, err := client.Do(reqClone)
		if err != nil {
			lastErr = err
			log.Printf("[DEBUG] Request failed (attempt %d/%d): %v", attempt+1, cfg.MaxRetries+1, err)
			if attempt < cfg.MaxRetries {
				time.Sleep(calculateBackoff(attempt, cfg))
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			if attempt < cfg.MaxRetries {
				time.Sleep(calculateBackoff(attempt, cfg))
			}
			continue
		}

		lastResp = resp
		lastBody = body

		// 2xx success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, body, nil
		}

		// 401 -- not retryable, fail fast
		if resp.StatusCode == 401 {
			return resp, body, fmt.Errorf("authentication failed (401): check your SNYK_TOKEN")
		}

		// 429 rate limit
		if resp.StatusCode == 429 {
			retryAfter := getRetryAfter(resp)
			if retryAfter == 0 {
				retryAfter = calculateBackoff(attempt, cfg)
			}
			log.Printf("[INFO] Rate limited (429), waiting %v (attempt %d/%d)", retryAfter, attempt+1, cfg.MaxRetries+1)
			if attempt < cfg.MaxRetries {
				time.Sleep(retryAfter)
			}
			continue
		}

		// Retryable server errors
		if isRetryableStatus(resp.StatusCode) {
			log.Printf("[INFO] Server error (%d), retrying (attempt %d/%d)", resp.StatusCode, attempt+1, cfg.MaxRetries+1)
			if attempt < cfg.MaxRetries {
				time.Sleep(calculateBackoff(attempt, cfg))
			}
			continue
		}

		// Non-retryable error -- return as-is for caller to handle
		return resp, body, nil
	}

	if lastErr != nil {
		return lastResp, lastBody, fmt.Errorf("max retries exceeded: %w", lastErr)
	}
	if lastResp != nil {
		return lastResp, lastBody, fmt.Errorf("max retries exceeded: status %d", lastResp.StatusCode)
	}
	return nil, nil, fmt.Errorf("max retries exceeded")
}
