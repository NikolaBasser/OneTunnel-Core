//go:build windows && !onetunnel_safety_test

package platform

func traceWFPCall(name string) func(uint32) { return nil }
