package profiles

import (
	"errors"
	"strings"

	"github.com/NikolaBasser/OneTunnel-Core/internal/control"
)

// Value fields keep user-preference transaction comparisons deterministic.
type BalanceInput struct {
	Enabled                bool
	Mode, ProfileIDs       string
	Best, Interval, MaxRTT int
}

func (b BalanceInput) snapshot(doc Document) (*control.Balance, error) {
	if !b.Enabled {
		return nil, nil
	}
	result := &control.Balance{Mode: b.Mode, Best: b.Best, Interval: b.Interval, MaxRTT: b.MaxRTT}
	seen := map[string]bool{}
	ids := strings.Split(b.ProfileIDs, ",")
	if len(ids) > 8 {
		return nil, errors.New("Выберите от 2 до 8 серверов для общего пула.")
	}
	for _, id := range ids {
		if !favoriteProfileIDPattern.MatchString(id) || seen[id] {
			return nil, errors.New("Проверьте список серверов балансировщика.")
		}
		seen[id] = true
		found := false
		for _, stored := range doc.Profiles {
			if stored.ID != id {
				continue
			}
			p, _, e := globalTransportProfile(stored, preferencesValue(doc.UserSettings))
			if e != nil {
				return nil, e
			}
			p.Network = nil
			p.Reliability = nil
			result.Members = append(result.Members, p)
			found = true
			break
		}
		if !found {
			return nil, errors.New("Сервер пула удалён. Выберите состав балансировщика заново.")
		}
	}
	if !control.ValidateBalance(result) {
		return nil, errors.New("Балансировщик: 2–8 серверов, лучших 1–8, проверка 15–300 секунд, задержка 100–10000 мс.")
	}
	return result, nil
}
