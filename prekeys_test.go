package whatsmeow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/signalerror"
	"golang.org/x/crypto/hkdf"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/gcmutil"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type sessionTestStore struct {
	store.NoopStore
	mu         sync.Mutex
	sessions   map[string][]byte
	identities map[string][32]byte
	lid        types.JID
	writeErr   error
}

func (s *sessionTestStore) HasSession(ctx context.Context, address string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[address] != nil, s.Error
}

func (s *sessionTestStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.sessions[address]), s.Error
}

func (s *sessionTestStore) PutSession(ctx context.Context, address string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.sessions[address] = bytes.Clone(data)
	return nil
}

func (s *sessionTestStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.identities[address]
	return !ok || previous == key, nil
}

func (s *sessionTestStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[address] = key
	return nil
}

func (s *sessionTestStore) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	lid := s.lid
	if !lid.IsEmpty() {
		lid.Device = pn.Device
	}
	return lid, s.Error
}

func newSessionTestClient() (*Client, *sessionTestStore) {
	s := &sessionTestStore{
		sessions: make(map[string][]byte), identities: make(map[string][32]byte),
		lid: types.NewJID("123456789", types.HiddenUserServer),
	}
	id := types.NewADJID("15550000001", 0, 1)
	device := &store.Device{
		ID: &id, IdentityKey: keys.NewKeyPair(), RegistrationID: 42,
		Sessions: s, Identities: s, LIDs: s,
	}
	return NewClient(device, nil), s
}

func sessionTestBundle(device types.JID) waBinary.Node {
	identity := keys.NewKeyPair()
	return waBinary.Node{
		Tag: "user", Attrs: waBinary.Attrs{"jid": device},
		Content: []waBinary.Node{
			{Tag: "registration", Content: []byte{0, 0, 0, 17}},
			{Tag: "identity", Content: identity.Pub[:]},
			preKeyToNode(identity.CreateSignedPreKey(1)),
			preKeyToNode(keys.NewPreKey(2)),
		},
	}
}

// Use the real IQ transport and bundle parser without a WhatsApp connection.
// Both ends share synthetic Noise keys; only the responder is simulated.
func connectSessionTestResponder(t *testing.T, cli *Client, respond func(*waBinary.Node) waBinary.Node) *atomic.Int32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	const pattern = "EnsureSession test transport"
	salt := sha256.Sum256([]byte(pattern))
	keyMaterial := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha256.New, nil, salt[:], nil), keyMaterial); err != nil {
		t.Fatal(err)
	}
	readKey, err := gcmutil.Prepare(keyMaterial[:32])
	if err != nil {
		t.Fatal(err)
	}
	writeKey, err := gcmutil.Prepare(keyMaterial[32:])
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		for counter := uint32(0); ; counter++ {
			_, frame, err := conn.Read(ctx)
			if err != nil {
				return
			}
			iv := make([]byte, 12)
			binary.BigEndian.PutUint32(iv[8:], counter)
			if len(frame) < 3 {
				t.Error("missing frame header")
				return
			}
			plaintext, err := readKey.Open(nil, iv, frame[3:], nil)
			if err != nil {
				t.Error(err)
				return
			}
			node, err := waBinary.Unmarshal(plaintext[1:])
			if err != nil {
				t.Error(err)
				return
			}
			count.Add(1)
			if node.Tag != "iq" || node.Attrs["xmlns"] != "encrypt" {
				t.Errorf("unexpected outgoing stanza: %s", node.Tag)
				return
			}
			response := respond(node)
			response.Tag = "iq"
			if response.Attrs == nil {
				response.Attrs = waBinary.Attrs{"type": "result"}
			}
			response.Attrs["id"] = node.Attrs["id"]
			data, err := waBinary.Marshal(response)
			if err != nil {
				t.Error(err)
				return
			}
			ciphertext := writeKey.Seal(nil, iv, data, nil)
			frame = append([]byte{byte(len(ciphertext) >> 16), byte(len(ciphertext) >> 8), byte(len(ciphertext))}, ciphertext...)
			if err = conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	fs := socket.NewFrameSocket(waLog.Noop, nil)
	fs.Header = nil
	fs.HTTPHeaders.Del("Origin")
	fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
	if err = fs.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	handshake := socket.NewNoiseHandshake()
	handshake.Start(pattern, nil)
	cli.socket, err = handshake.Finish(fs, func(ctx context.Context, data []byte) {
		node, err := waBinary.Unmarshal(data[1:])
		if err != nil {
			t.Error(err)
			return
		}
		cli.receiveResponse(ctx, node)
	}, func(context.Context, *socket.NoiseSocket, bool) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.socket.Stop(true, true) })
	return count
}

func TestEnsureSessionEstablishesAndReuses(t *testing.T) {
	for _, deviceID := range []uint16{0, 5} {
		t.Run(fmt.Sprintf("device_%d", deviceID), func(t *testing.T) {
			cli, s := newSessionTestClient()
			pn := types.NewJID("15550000002", types.DefaultUserServer)
			pn.Device = deviceID
			lid := s.lid
			lid.Device = deviceID
			bundle := sessionTestBundle(lid)
			count := connectSessionTestResponder(t, cli, func(node *waBinary.Node) waBinary.Node {
				key := node.GetChildByTag("key")
				requested := key.GetChildByTag("user")
				if requested.Attrs["jid"] != lid {
					t.Errorf("requested %v, expected %v", requested.Attrs["jid"], lid)
				}
				return waBinary.Node{Content: []waBinary.Node{{Tag: "list", Content: []waBinary.Node{bundle}}}}
			})
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if err := cli.EnsureSession(t.Context(), pn); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			address := lid.SignalAddress().String()
			before, _ := s.GetSession(t.Context(), address)
			if len(before) == 0 || count.Load() != 1 {
				t.Fatalf("session bytes=%d, prekey requests=%d", len(before), count.Load())
			}
			if err := cli.EnsureSession(t.Context(), lid); err != nil {
				t.Fatal(err)
			}
			after, _ := s.GetSession(t.Context(), address)
			if !bytes.Equal(before, after) || count.Load() != 1 {
				t.Fatal("existing session was changed or prekeys refetched")
			}
			cli.socket.Stop(true, true)
			if err := cli.EnsureSession(t.Context(), lid); err != nil {
				t.Fatalf("existing session requires a connection: %v", err)
			}
			if _, _, err := cli.encryptMessageForDevice(t.Context(), []byte("test"), lid, nil, nil, nil); err != nil {
				t.Fatalf("established session cannot encrypt: %v", err)
			}
		})
	}
}

func TestEnsureSessionRechecksAfterFetch(t *testing.T) {
	cli, s := newSessionTestClient()
	device := s.lid
	bundleNode := sessionTestBundle(device)
	established := make(chan []byte, 1)
	connectSessionTestResponder(t, cli, func(*waBinary.Node) waBinary.Node {
		bundle, err := nodeToPreKeyBundle(0, bundleNode)
		if err != nil {
			t.Error(err)
			return waBinary.Node{}
		}
		builder := session.NewBuilderFromSignal(cli.Store, device.SignalAddress(), pbSerializer)
		if err = builder.ProcessBundle(t.Context(), bundle); err != nil {
			t.Error(err)
		}
		data, _ := s.GetSession(t.Context(), device.SignalAddress().String())
		established <- data
		return waBinary.Node{Content: []waBinary.Node{{Tag: "list", Content: []waBinary.Node{bundleNode}}}}
	})
	if err := cli.EnsureSession(t.Context(), device); err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetSession(t.Context(), device.SignalAddress().String())
	before := <-established
	if len(before) == 0 || !bytes.Equal(before, after) {
		t.Fatal("session established during prekey fetch was replaced")
	}
}

func TestEnsureSessionCanRetryAfterFailure(t *testing.T) {
	cli, s := newSessionTestClient()
	device := s.lid
	bundle := sessionTestBundle(device)
	attempt := 0
	connectSessionTestResponder(t, cli, func(*waBinary.Node) waBinary.Node {
		attempt++
		if attempt == 1 {
			return waBinary.Node{Content: []waBinary.Node{{Tag: "list"}}}
		}
		return waBinary.Node{Content: []waBinary.Node{{Tag: "list", Content: []waBinary.Node{bundle}}}}
	})
	if err := cli.EnsureSession(t.Context(), device); err == nil {
		t.Fatal("expected first attempt to fail")
	}
	if err := cli.EnsureSession(t.Context(), device); err != nil {
		t.Fatalf("failed setup prevented retry: %v", err)
	}
}

func TestEnsureSessionFailures(t *testing.T) {
	for _, scenario := range []string{"missing device", "device error", "invalid bundle", "invalid signature", "untrusted identity", "store failure", "IQ error"} {
		t.Run(scenario, func(t *testing.T) {
			cli, s := newSessionTestClient()
			device := s.lid
			bundle := sessionTestBundle(device)
			previous := *keys.NewKeyPair().Pub
			if scenario == "untrusted identity" {
				s.identities[device.SignalAddress().String()] = previous
			}
			writeErr := errors.New("session write failed")
			if scenario == "store failure" {
				s.writeErr = writeErr
			}
			connectSessionTestResponder(t, cli, func(*waBinary.Node) waBinary.Node {
				switch scenario {
				case "missing device":
					return waBinary.Node{Content: []waBinary.Node{{Tag: "list"}}}
				case "device error":
					bundle.Content = []waBinary.Node{{Tag: "error", Attrs: waBinary.Attrs{"code": "404"}}}
				case "invalid bundle":
					bundle.Content = nil
				case "invalid signature":
					signedKey := bundle.GetChildByTag("skey")
					signature := signedKey.GetChildByTag("signature").Content.([]byte)
					signature[0] ^= 1
				case "IQ error":
					return waBinary.Node{Attrs: waBinary.Attrs{"type": "error"}, Content: []waBinary.Node{{Tag: "error", Attrs: waBinary.Attrs{"code": "500"}}}}
				}
				return waBinary.Node{Content: []waBinary.Node{{Tag: "list", Content: []waBinary.Node{bundle}}}}
			})
			err := cli.EnsureSession(t.Context(), device)
			if err == nil {
				t.Fatal("expected failure")
			}
			if scenario == "untrusted identity" {
				if !errors.Is(err, signalerror.ErrUntrustedIdentity) || s.identities[device.SignalAddress().String()] != previous {
					t.Fatalf("identity trust was not preserved: %v", err)
				}
			}
			if scenario == "store failure" && !errors.Is(err, writeErr) {
				t.Fatalf("lost persistence error: %v", err)
			}
			if len(s.sessions) != 0 {
				t.Fatal("failed operation persisted a session")
			}
		})
	}
}

func TestEnsureSessionLocalChecks(t *testing.T) {
	cli, s := newSessionTestClient()
	if err := (*Client)(nil).EnsureSession(t.Context(), s.lid); !errors.Is(err, ErrClientIsNil) {
		t.Fatal(err)
	}
	for _, device := range []types.JID{{}, types.NewJID("123", types.GroupServer)} {
		if err := cli.EnsureSession(t.Context(), device); err == nil {
			t.Fatal("invalid device accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := cli.EnsureSession(ctx, s.lid); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := cli.EnsureSession(t.Context(), s.lid); !errors.Is(err, ErrNotConnected) {
		t.Fatal(err)
	}
	s.Error = errors.New("store read failed")
	if err := cli.EnsureSession(t.Context(), s.lid); !errors.Is(err, s.Error) {
		t.Fatal(err)
	}
	s.Error = nil
	s.lid = types.EmptyJID
	if err := cli.EnsureSession(t.Context(), types.NewJID("15550000002", types.DefaultUserServer)); err == nil {
		t.Fatal("missing LID mapping accepted")
	}
	cli.Store.ID = nil
	if err := cli.EnsureSession(t.Context(), types.NewJID("123", types.HiddenUserServer)); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal(err)
	}
}
