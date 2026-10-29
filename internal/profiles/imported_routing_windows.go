package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/NikolaBasser/OneTunnel-Core/internal/protocol"
)

type ImportedRoutingSource struct {
	Group, SHA256 string
	Profiles      []ProviderRoutingChoice
}

func recordImportedRouting(doc *Document, group string, batch ImportResult) {
	if len(batch.ImportedRouting) == 0 {
		delete(doc.ImportedRouting, group)
		return
	}
	if doc.ImportedRouting == nil {
		doc.ImportedRouting = map[string]json.RawMessage{}
	}
	doc.ImportedRouting[group] = append(json.RawMessage(nil), batch.ImportedRouting...)
}
func normalizeImportedRouting(doc *Document) error {
	groups := map[string]bool{}
	for _, p := range doc.Profiles {
		groups[p.Group] = true
	}
	total := 0
	for group, raw := range doc.ImportedRouting {
		if !groups[group] {
			delete(doc.ImportedRouting, group)
			continue
		}
		total += len(raw)
		if len(raw) > MaxBytes || total > 4*MaxBytes || !boundedJSON(raw) {
			return ErrImport
		}
		var configs []any
		if json.Unmarshal(raw, &configs) != nil || len(configs) == 0 || len(configs) > 256 {
			return ErrImport
		}
		clean := subscriptionRoutingSnapshot(configs)
		if len(clean) == 0 {
			return ErrImport
		}
		doc.ImportedRouting[group] = clean
	}
	return nil
}
func (a *Application) importedRoutingSources() ([]ImportedRoutingSource, error) {
	doc, e := a.Store.Load()
	if e != nil {
		return nil, e
	}
	groups := make([]string, 0, len(doc.ImportedRouting))
	for group := range doc.ImportedRouting {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	result := []ImportedRoutingSource{}
	for _, group := range groups {
		list, e := parseProviderRouting(context.Background(), doc.ImportedRouting[group], ProviderRoutingInput{Index: -1}, nil)
		if e != nil {
			return nil, e
		}
		result = append(result, ImportedRoutingSource{Group: group, SHA256: list.SHA256, Profiles: list.Profiles})
	}
	return result, nil
}
func (a *Application) selectImportedRouting(ctx context.Context, group string, input *ProviderRoutingInput) (ProviderRoutingResult, error) {
	if input == nil || input.Index < 0 {
		return ProviderRoutingResult{}, ErrImport
	}
	doc, e := a.Store.Load()
	if e != nil {
		return ProviderRoutingResult{}, e
	}
	raw := doc.ImportedRouting[group]
	if len(raw) == 0 {
		return ProviderRoutingResult{}, errors.New("Маршрутизация подписки ещё не импортирована. Обновите подписку в списке серверов.")
	}
	list, e := parseProviderRouting(ctx, raw, ProviderRoutingInput{Index: -1}, nil)
	if e != nil {
		return ProviderRoutingResult{}, e
	}
	if input.SHA256 != list.SHA256 {
		return ProviderRoutingResult{}, errors.New("Подписка обновилась. Откройте настройки заново и выберите актуальную конфигурацию.")
	}
	source := doc.SubscriptionSources[group]
	if !validProviderURL(source) {
		source = "https://imported.invalid/snapshot"
	}
	cache := map[string][]byte{}
	result, e := parseProviderRouting(ctx, raw, ProviderRoutingInput{URL: source, Index: input.Index, SHA256: list.SHA256}, func(format, category string) (*protocol.RuleSetData, error) {
		data, ok := cache[format]
		if !ok {
			var err error
			data, err = downloadLoyal(ctx, format, category)
			if err != nil {
				return nil, err
			}
			cache[format] = data
		}
		return protocol.ImportLoyalsoldier(format, category, data)
	})
	if e != nil {
		return result, e
	}
	var catalog []presetSource
	if json.Unmarshal([]byte(result.Draft.PresetConfigText), &catalog) != nil || len(catalog) != 1 {
		return ProviderRoutingResult{}, ErrImport
	}
	catalog[0].Group = group
	result.Draft.PresetConfigText = encodePresetCatalog(catalog)
	return result, nil
}
