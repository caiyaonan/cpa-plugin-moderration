package policy

// Glob reports whether name matches pattern, where '*' matches any run of
// characters (including none) and '?' matches exactly one character.
// Matching is case-sensitive and works on runes. It runs in O(len(p)*len(n)).
func Glob(pattern, name string) bool {
	p := []rune(pattern)
	n := []rune(name)
	pi, ni := 0, 0
	starP, starN := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			starP, starN = pi, ni
			pi++
		case starP >= 0:
			starN++
			pi, ni = starP+1, starN
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
