package socket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"

	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestFrameCloseConcurrentWithNoiseStop(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"web.whatsapp.com"}})
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		_, _, _ = conn.Read(r.Context())
	}))
	defer peer.Close()

	fs := NewFrameSocket(waLog.Noop, peer.Client())
	fs.URL = "ws" + strings.TrimPrefix(peer.URL, "http")
	if err := fs.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer fs.Close(0)
	ns, err := newNoiseSocket(fs, nil, nil, nil, func(context.Context, *NoiseSocket, bool) {})
	if err != nil {
		t.Fatal(err)
	}

	// Hold Close immediately before its callback read, then let Stop begin.
	// Stop signals its consumer before reaching the callback setter.
	closing := make(chan struct{})
	cancel := fs.cancel
	fs.cancel = func() {
		close(closing)
		<-ns.stopConsumer
		cancel()
	}
	var work sync.WaitGroup
	work.Go(func() { fs.Close(0) })
	work.Go(func() {
		<-closing
		ns.Stop(true, false)
	})
	work.Wait()
	if fs.IsConnected() {
		t.Fatal("socket is still connected after both close paths returned")
	}
}
