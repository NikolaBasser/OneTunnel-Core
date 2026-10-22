package platform

type nativeEngine interface {
	Close() error
	Done() <-chan struct{}
}

func nativeExited(engine nativeEngine) bool {
	if engine == nil {
		return true
	}
	select {
	case <-engine.Done():
		return true
	default:
		return false
	}
}
