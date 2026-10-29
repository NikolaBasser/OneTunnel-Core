package control

// Balance is a bounded snapshot; subscription membership never changes a live pool.
type Balance struct {
	Mode      string
	Best      int
	Interval  int
	MaxRTT    int
	Members   []Profile
	Automatic bool `json:",omitempty"`
}

func ValidateBalance(b *Balance) bool {
	if b == nil {
		return true
	}
	minMembers, maxMembers := 2, 8
	if b.Automatic {
		minMembers, maxMembers = 1, 4096
	}
	return (b.Mode == "best" || b.Mode == "balanced") && len(b.Members) >= minMembers && len(b.Members) <= maxMembers && b.Best >= 1 && b.Best <= 8 && (b.Automatic || b.Best <= len(b.Members)) && b.Interval >= 15 && b.Interval <= 300 && b.MaxRTT >= 100 && b.MaxRTT <= 10000
}
