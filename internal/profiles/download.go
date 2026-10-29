package profiles

import (
	"context"
	"errors"
	"github.com/NikolaBasser/OneTunnel-Core/internal/buildinfo"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func Download(ctx context.Context, source string) (ImportResult, error) {
	client := subscriptionClient()
	defer client.CloseIdleConnections()
	return downloadWithClient(ctx, source, client)
}

func subscriptionClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || !SecureURL(r.URL.String()) {
			return errors.New("redirect refused")
		}
		return nil
	}}
}
func downloadWithClient(ctx context.Context, source string, client *http.Client) (ImportResult, error) {
	if !SecureURL(source) {
		return ImportResult{}, errors.New("Для подписки нужна HTTPS-ссылка без встроенного логина и пароля.")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", source, nil)
	if e != nil {
		return ImportResult{}, ErrImport
	}
	req.Header.Set("User-Agent", "v2rayN/7.0 OneTunnel/"+buildinfo.Version)
	req.Header.Set("Accept", "application/json, text/plain;q=0.9")
	response, e := client.Do(req)
	if e != nil {
		return ImportResult{}, errors.New("Не удалось обновить подписку. Проверь сеть, HTTPS-адрес и сертификат сервера.")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > MaxBytes {
		return ImportResult{}, errors.New("Подписка недоступна или больше 4 МБ.")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if e != nil || len(b) > MaxBytes {
		return ImportResult{}, errors.New("Не удалось прочитать подписку либо она больше 4 МБ.")
	}
	defer clear(b)
	result, err := ParseSubscription(string(b))
	if err != nil {
		return ImportResult{}, err
	}
	result.Metadata = ParseSubscriptionUserinfo(response.Header.Values("Subscription-Userinfo"))
	return result, nil
}

// ParseSubscriptionUserinfo returns nil for absent or invalid recognized metadata.
func ParseSubscriptionUserinfo(values []string) *SubscriptionMetadata {
	if len(values) != 1 || len(values[0]) > 4096 {
		return nil
	}
	metadata := &SubscriptionMetadata{}
	seen := map[string]bool{}
	for _, field := range strings.Split(values[0], ";") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name == "upload" || name == "download" || name == "total" || name == "expire" {
				return nil
			}
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		var target **uint64
		switch name {
		case "upload":
			target = &metadata.Upload
		case "download":
			target = &metadata.Download
		case "total":
			target = &metadata.Total
		case "expire":
			target = &metadata.Expire
		default:
			continue
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		digits := strings.TrimSpace(parts[1])
		if digits == "" {
			return nil
		}
		for i := 0; i < len(digits); i++ {
			if digits[i] < '0' || digits[i] > '9' {
				return nil
			}
		}
		value, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || name == "expire" && value > 253402300799 {
			return nil
		}
		*target = &value
	}
	if len(seen) == 0 {
		return nil
	}
	return metadata
}
