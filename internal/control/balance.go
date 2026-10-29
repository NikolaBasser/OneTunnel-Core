package control

// Balance is a bounded snapshot; subscription membership never changes a live pool.
type Balance struct {
	Mode     string
	Best     int
	Interval int
	MaxRTT   int
	Members  []Profile
}

func ValidateBalance(b *Balance) bool {
	if b == nil {
		return true
	}
	return (b.Mode == "best" || b.Mode == "balanced") && len(b.Members) >= 2 && len(b.Members) <= 8 && b.Best >= 1 && b.Best <= len(b.Members) && b.Interval >= 15 && b.Interval <= 300 && b.MaxRTT >= 100 && b.MaxRTT <= 10000
}
