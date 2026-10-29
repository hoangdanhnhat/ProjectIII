package eventlog

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
)

// This file implements the wevtutil /f:xml renderer output parse. The exact
// shape (rendered client-side XML) is stable in Windows event logs:
//
//	<Events>
//	  <Event xmlns=".../event">
//	    <System> <Provider Name=.. /> <TimeCreated SystemTime=.. />
//	            <EventRecordID>..</EventRecordID> <Computer>..</Computer>
//	            <EventID Qualifiers=..>..</EventID> <Level>..</Level> ...
//	    </System>
//	    <EventData> <Data Name=..>value</Data> ... </EventData>
//	  </Event>
//	</Events>
//
// Element namespaces differ between endpoints, so matching is done on local
// names only. Anything unexpected (RenderingInfo, TimeCreated attributes we
// do not use) is ignored: collecting a subset with the right meaning is
// preferable to failing the whole channel on a shape we did not predict.

// node is a minimal parsed XML element.
type node struct {
	name     string // local name, namespace ignored
	attrs    map[string]string
	children []*node
	text     []string // interleaved char data
}

// attr returns an attribute value, empty when missing.
func (n *node) attr(name string) string { return n.attrs[name] }

// child returns the first child with that local name.
func (n *node) child(name string) *node {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// childrenOf returns all direct children with that local name.
func (n *node) childrenOf(name string) []*node {
	var out []*node
	for _, c := range n.children {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// text returns concatenated char data with surrounding whitespace trimmed.
func (n *node) string() string { return strings.TrimSpace(strings.Join(n.text, "")) }

// parseTree parses an XML document into a forest of nodes rooted at a
// synthetic document node (real documents may contain XML prologs and
// multiple top-level events).
func parseTree(data []byte) (*node, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false // renderer output may contain non-clean entities; be liberal in what we accept
	doc := &node{name: "#document"}
	stack := []*node{doc}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		parent := stack[len(stack)-1]
		switch t := tok.(type) {
		case xml.StartElement:
			c := &node{name: t.Name.Local, attrs: make(map[string]string, len(t.Attr))}
			for _, a := range t.Attr {
				if a.Name.Local == "xmlns" || strings.HasPrefix(a.Name.Local, "xmlns:") {
					continue // namespace declarations are structural noise
				}
				c.attrs[a.Name.Local] = a.Value
			}
			parent.children = append(parent.children, c)
			stack = append(stack, c)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			parent.text = append(parent.text, string(t))
		}
	}
	if len(stack) != 1 {
		return nil, errors.New("unclosed XML elements")
	}
	return doc, nil
}

// allEvents returns every Event element anywhere in the tree (Documents
// contain a single <Events> wrapper, but the parse tolerates delimiters).
func allEvents(n *node) []*node {
	var out []*node
	if n.name == "Event" {
		out = append(out, n)
	}
	for _, c := range n.children {
		out = append(out, allEvents(c)...)
	}
	return out
}

// buildEvents converts parsed Event elements, skipping malformed ones; the
// count of skipped elements is returned so the caller can note it.
func buildEvents(doc *node) (events []Event, skipped int) {
	for _, e := range allEvents(doc) {
		sys := e.child("System")
		if sys == nil {
			skipped++ // a System-less Event is not analyzable; ignore
			continue
		}
		ev := Event{
			Provider:    attrOrEmpty(sys.child("Provider"), "Name"),
			TimeCreated: attrOrEmpty(sys.child("TimeCreated"), "SystemTime"),
			Computer:    sys.child("Computer").stringOf(),
			EventID:     atoiOrZero(sys.child("EventID").stringOf()),
			Level:       atoiInt(sys.child("Level").stringOf()),
			RecordID:    atou64(sys.child("EventRecordID").stringOf()),
		}
		for _, d := range e.child("EventData").directData() {
			ev.Data = append(ev.Data, d)
		}
		events = append(events, ev)
	}
	return events, skipped
}

// directData extracts the named <Data> elements of an <EventData> node.
func (n *node) directData() []DataField {
	if n == nil {
		return nil
	}
	var out []DataField
	for _, d := range n.childrenOf("Data") {
		if name := d.attr("Name"); name != "" {
			out = append(out, DataField{Name: name, Value: d.string()})
		}
	}
	return out
}

// attrOrEmpty returns the attribute or "" when the node is missing.
func attrOrEmpty(n *node, name string) string {
	if n == nil {
		return ""
	}
	return n.attr(name)
}

// stringOf is string() with nil-safe behavior for missing nodes.
func (n *node) stringOf() string {
	if n == nil {
		return ""
	}
	return n.string()
}

func atoiOrZero(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func atoiInt(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func atou64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// decodeEvents parses wevtutil XML output into events.
func decodeEvents(data []byte) ([]Event, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("wevtutil output is empty")
	}
	doc, err := parseTree(data)
	if err != nil {
		return nil, err
	}
	events, _ := buildEvents(doc)
	return events, nil
}
