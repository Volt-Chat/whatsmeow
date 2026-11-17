package whatsmeow

import (
	"context"
	"errors"
	"testing"

	"go.mau.fi/whatsmeow/appstate"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type snapshotContactStore struct {
	store.ContactStore
	batches [][]store.ContactEntry
	writes  []store.ContactEntry
	err     error
}

func (s *snapshotContactStore) PutAllContactNames(_ context.Context, names []store.ContactEntry) error {
	s.batches = append(s.batches, names)
	return s.err
}

func (s *snapshotContactStore) PutContactName(_ context.Context, jid types.JID, first, full string) error {
	s.writes = append(s.writes, store.ContactEntry{JID: jid, FirstName: first, FullName: full})
	return s.err
}

func TestFullContactSnapshotBatchesWritesAndPreservesEvents(t *testing.T) {
	contacts := &snapshotContactStore{}
	client := NewClient(&store.Device{Contacts: contacts}, nil)
	client.EmitAppStateEventsOnFullSync = true
	jid := types.NewJID("10000000000", types.DefaultUserServer)
	name := appstate.BuildContact(jid, "Saved contact", true)
	edit := appstate.BuildLabelEdit("42", "Customers", 2, false)
	link := appstate.BuildLabelChat(jid, "42", true)
	mutations := []appstate.Mutation{
		{Index: name.Mutations[0].Index, Action: name.Mutations[0].Value, Operation: name.Operation},
		{Index: edit.Mutations[0].Index, Action: edit.Mutations[0].Value, Operation: edit.Operation},
		{Index: link.Mutations[0].Index, Action: link.Mutations[0].Value, Operation: link.Operation},
	}

	var queued []any
	if err := client.collectEventsToDispatch(t.Context(), name.Type, mutations, true, &queued); err != nil {
		t.Fatal(err)
	}
	if len(contacts.batches) != 1 || len(contacts.batches[0]) != 1 || contacts.batches[0][0].FullName != "Saved contact" || len(contacts.writes) != 0 {
		t.Fatalf("full sync writes: batches=%v individual=%v", contacts.batches, contacts.writes)
	}
	if len(queued) != 6 {
		t.Fatalf("queued %d events, want raw and typed events for all mutations", len(queued))
	}
	for i, mutation := range mutations {
		raw, ok := queued[i*2].(*events.AppState)
		if !ok || raw.SyncActionValue != mutation.Action {
			t.Fatalf("raw event at position %d: %T", i*2, queued[i*2])
		}
	}
	contact, contactOK := queued[1].(*events.Contact)
	label, labelOK := queued[3].(*events.LabelEdit)
	linkEvent, linkOK := queued[5].(*events.LabelAssociationChat)
	if !contactOK || !contact.FromFullSync || contact.JID != jid ||
		!labelOK || !label.FromFullSync || label.LabelID != "42" ||
		!linkOK || !linkEvent.FromFullSync || linkEvent.JID != jid || !linkEvent.Action.GetLabeled() {
		t.Fatalf("unexpected typed events: %T, %T, %T", queued[1], queued[3], queued[5])
	}

	queued = nil
	if err := client.collectEventsToDispatch(t.Context(), name.Type, mutations[:1], false, &queued); err != nil {
		t.Fatal(err)
	}
	if len(contacts.batches) != 1 || len(contacts.writes) != 1 || contacts.writes[0].FullName != "Saved contact" {
		t.Fatalf("incremental sync did not write the contact individually: %v", contacts.writes)
	}

	queued = nil
	contacts.err = errors.New("store unavailable")
	err := client.collectEventsToDispatch(t.Context(), name.Type, mutations, true, &queued)
	if !errors.Is(err, contacts.err) || len(queued) != 0 {
		t.Fatalf("failed snapshot returned err=%v and %d events", err, len(queued))
	}
}
