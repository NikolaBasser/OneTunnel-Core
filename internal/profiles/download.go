package profiles

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

func Download(ctx context.Context, source string) (ImportResult, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || !SecureURL(r.URL.String()) {
			return errors.New("redirect refused")
		}
		return nil
	}}
	defer client.CloseIdleConnections()
	return downloadWithClient(ctx, source, client)
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
	req.Header.Set("User-Agent", "v2rayN/7.0 OneTunnel/0.2.0")
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
	return ParseSubscription(string(b))
}
