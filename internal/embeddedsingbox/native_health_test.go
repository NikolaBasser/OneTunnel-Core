package embeddedsingbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
)

type nativeHealthDNS struct {
	response *dns.Msg
	err      error
	options  adapter.DNSQueryOptions
	question dns.Question
	deadline time.Time
}

func (f *nativeHealthDNS) Exchange(ctx context.Context, query *dns.Msg, options adapter.DNSQueryOptions) (*dns.Msg, error) {
	f.options = options
	f.question = query.Question[0]
	f.deadline, _ = ctx.Deadline()
	if f.err != nil {
		return nil, f.err
	}
	if f.response != nil {
		return f.response, nil
	}
	response := new(dns.Msg)
	response.SetReply(query)
	response.Rcode = dns.RcodeNameError // Any well-formed reply proves the encrypted policy DNS path answered.
	return response, nil
}

func TestNativeHealthUsesUncachedPolicyDNSAndValidatesResponse(t *testing.T) {
	router := &nativeHealthDNS{}
	engine := &Engine{native: validationNativeTransport{}, nativeDNS: router}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := engine.NativeHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if router.question.Name != "." || router.question.Qtype != dns.TypeNS || router.question.Qclass != dns.ClassINET {
		t.Fatalf("health query = %+v", router.question)
	}
	if !router.options.DisableCache || !router.options.DisableOptimisticCache {
		t.Fatalf("health check did not bypass caches: %+v", router.options)
	}
	if remaining := time.Until(router.deadline); remaining > 5*time.Second || remaining <= 0 {
		t.Fatalf("health query deadline is not bounded to five seconds: %v", remaining)
	}

	router.response = new(dns.Msg)
	if err := engine.NativeHealth(ctx); err == nil {
		t.Fatal("accepted a nil-question response")
	}
	router.response = new(dns.Msg)
	router.response.SetQuestion("wrong.example.", dns.TypeNS)
	router.response.Response = true
	if err := engine.NativeHealth(ctx); err == nil {
		t.Fatal("accepted a mismatched response question")
	}
}

func TestNativeHealthFailsClosedWithoutNativeDNSOrWithExchangeError(t *testing.T) {
	ctx := context.Background()
	if err := (&Engine{}).NativeHealth(ctx); err == nil {
		t.Fatal("proxy-only engine exposed native health")
	}
	if err := (&Engine{native: validationNativeTransport{}}).NativeHealth(ctx); err == nil {
		t.Fatal("missing policy DNS router was accepted")
	}
	router := &nativeHealthDNS{err: errors.New("synthetic DNS failure")}
	if err := (&Engine{native: validationNativeTransport{}, nativeDNS: router}).NativeHealth(ctx); err == nil {
		t.Fatal("DNS exchange error was accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := (&Engine{native: validationNativeTransport{}, nativeDNS: &nativeHealthDNS{}}).NativeHealth(canceled); err == nil {
		t.Fatal("canceled health query was accepted")
	}

	engine, err := StartWithNativeTransport([]byte(`{"outbounds":[{"type":"onetunnel-native","tag":"proxy"}]}`), true, validationNativeTransport{})
	if err != nil {
		t.Fatalf("start synthetic native engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if engine.nativeDNS == nil {
		t.Fatal("native engine did not retain its configured sing-box DNS router")
	}
}
