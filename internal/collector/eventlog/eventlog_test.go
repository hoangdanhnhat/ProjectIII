package eventlog

import (
	"testing"
	"time"
)

// sampleXML mirrors the wevtutil qe <channel> /f:xml /rd:true renderer
// output: an <Events> root, namespaced <Event> elements, System fields with
// attributes, and named EventData values. It comes pre-sorted or not in the
// wild; Render's job is to make that irrelevant.
const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events">
 <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
   <Provider Name="Microsoft-Windows-Kernel-General"/>
   <TimeCreated SystemTime="2026-10-27T09:15:04.1234500Z"/>
   <EventRecordID>22013</EventRecordID>
   <Computer>win-host</Computer>
   <EventID Qualifiers="8">16</EventID>
   <Level>4</Level>
  </System>
  <EventData>
   <Data Name="StartTime">2026-10-26T22:00:00.000000000Z</Data>
   <Data Name="NewTime">2026-10-27T09:15:04.000000000Z</Data>
  </EventData>
 </Event>
 <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
   <Provider Name="Microsoft-Windows-Service-Control-Manager"/>
   <TimeCreated SystemTime="2026-10-27T09:05:00.0000000Z"/>
   <EventRecordID>22007</EventRecordID>
   <Computer>win-host</Computer>
   <EventID>7040</EventID>
   <Level>4</Level>
  </System>
  <EventData>
   <Data Name="param2">Windows Modules Installer</Data>
  </EventData>
 </Event>
</Events>`

func TestDecodeEvents(t *testing.T) {
	events, err := decodeEvents([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d, want 2: %+v", len(events), events)
	}
	first := events[0]
	if first.Provider != "Microsoft-Windows-Kernel-General" ||
		first.TimeCreated != "2026-10-27T09:15:04.1234500Z" ||
		first.RecordID != 22013 || first.Computer != "win-host" ||
		first.EventID != 16 || first.Level != 4 {
		t.Fatalf("system fields: %+v", first)
	}
	// Data fields present even if the XML arrives unsorted; Render sorts.
	if len(first.Data) != 2 || first.Data[0].Name != "StartTime" {
		t.Fatalf("event data: %+v", first.Data)
	}
}

func TestRenderIsDeterministicAndSorted(t *testing.T) {
	events, err := decodeEvents([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	since := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	render := func() string {
		return string(Render(&ChannelEvents{
			SchemaVersion: 1, Channel: "System", CapturedAt: at, Since: &since, Events: events,
		}))
	}
	first, second := render(), render()
	if first != second {
		t.Fatal("two renders of the same input differ:\n" + first + "\n---\n" + second)
	}
	// Newer record (22013) must come after the older one chronologically.
	if len(events) != 2 || events[0].RecordID != 22007 {
		t.Fatalf("sort order: %+v", events)
	}
}

func TestEmptyAndGarbageInput(t *testing.T) {
	if _, err := decodeEvents(nil); err == nil {
		t.Fatal("empty input must be an error")
	}
	if _, err := decodeEvents([]byte("<Events><Event>unclosed")); err == nil {
		t.Fatal("unclosed XML must be an error")
	}
}

func TestSinceQueryFormat(t *testing.T) {
	at := time.Date(2026, 10, 27, 9, 15, 4, 123000000, time.UTC)
	want := "*[System[TimeCreated[@SystemTime>='2026-10-27T09:15:04.123Z']]]"
	if got := sinceQuery(at); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSafeFilename(t *testing.T) {
	if got := safeFilename("Microsoft-Windows-PowerShell/Operational"); got != "Microsoft-Windows-PowerShell_Operational" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateChannel(t *testing.T) {
	bad := []string{"", "-c", "/q:*", "Sys\x01tem", "\r\n"}
	for _, ch := range bad {
		if err := validateChannel(ch); err == nil {
			t.Fatalf("validateChannel(%q) must fail", ch)
		}
	}
	if err := validateChannel("Microsoft-Windows-PowerShell/Operational"); err != nil {
		// A slash inside the name is required for many channels; only a
		// leading one is an option.
		t.Fatalf("embedded slash rejected: %v", err)
	}
}
