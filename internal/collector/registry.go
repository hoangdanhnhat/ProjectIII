package collector

// Registry maps scenario IDs to their collectors. The agent builds it once
// at startup, so the set of scenarios a binary supports is explicit in main.
type Registry struct {
	byID map[string]Collector
}

// NewRegistry returns a registry of the given collectors. Duplicate scenario
// IDs panic: they are a programming error caught on first run.
func NewRegistry(cs ...Collector) *Registry {
	r := &Registry{byID: make(map[string]Collector, len(cs))}
	for _, c := range cs {
		if _, dup := r.byID[c.ID()]; dup {
			panic("collector: duplicate scenario " + c.ID())
		}
		r.byID[c.ID()] = c
	}
	return r
}

// Lookup returns the collector registered for a scenario ID.
func (r *Registry) Lookup(id string) (Collector, bool) {
	c, ok := r.byID[id]
	return c, ok
}

// Supports reports whether the collector is implemented for goos.
func Supports(c Collector, goos string) bool {
	for _, p := range c.Platforms() {
		if p == goos {
			return true
		}
	}
	return false
}
