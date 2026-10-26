//go:build windows

package platform

import (
	"errors"
	"reflect"
	"testing"
)

func TestWinINetChangeNotificationsUseDocumentedOrder(t *testing.T) {
	got := []uintptr{}
	if err := notifyInternetOptions(func(value uintptr) error { got = append(got, value); return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uintptr{39, 37}) {
		t.Fatalf("notification order %v", got)
	}
}

func TestWinINetNotificationStopsOnFailure(t *testing.T) {
	expected := errors.New("synthetic notify failure")
	got := []uintptr{}
	err := notifyInternetOptions(func(value uintptr) error {
		got = append(got, value)
		if value == 39 {
			return expected
		}
		return nil
	})
	if !errors.Is(err, expected) || !reflect.DeepEqual(got, []uintptr{39}) {
		t.Fatalf("got calls %v err %v", got, err)
	}
}
