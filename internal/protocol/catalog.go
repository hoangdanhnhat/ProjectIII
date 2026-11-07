package protocol

// Scenario describes one collection scenario the server accepts: its ID and
// the artifact kinds its collectors may upload. The server validates job
// creation and artifact uploads against this catalog; the agent registers
// the matching collector packages.
type Scenario struct {
	ID    string
	Kinds []Kind
}

// Scenarios is the catalog of supported scenarios. Adding a scenario here
// and a collector package on the agent is the whole process.
var Scenarios = []Scenario{
	{ID: ScenarioWebshell, Kinds: []Kind{KindUpload, KindApacheLog, KindIISLog}},
	{ID: ScenarioNetstat, Kinds: []Kind{KindNetstatSnapshot, KindTIReport}},
	{ID: ScenarioEventlog, Kinds: []Kind{KindEventLog}},
	{ID: ScenarioHostRole, Kinds: []Kind{KindHostRole}},
}

// ScenarioByID looks up a scenario in the catalog.
func ScenarioByID(id string) (Scenario, bool) {
	for _, s := range Scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// AcceptsKind reports whether the scenario allows an artifact kind.
func (s Scenario) AcceptsKind(k Kind) bool {
	for _, allowed := range s.Kinds {
		if allowed == k {
			return true
		}
	}
	return false
}

// ScenarioIDs lists the catalog IDs, for the /v1/meta endpoint.
func ScenarioIDs() []string {
	ids := make([]string, len(Scenarios))
	for i, s := range Scenarios {
		ids[i] = s.ID
	}
	return ids
}
