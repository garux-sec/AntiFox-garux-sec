package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"antifox/agent"
)

// convHub is a tiny per-conversation pub/sub for ephemeral live-typing events.
// Events are NOT persisted (that is conversation_activities' job) — they exist
// only to stream token deltas to any open SSE client while a turn runs, so the
// chat UI can type the answer out as it arrives instead of waiting for the whole
// step to land in the DB and be picked up by the 1s poll.
type convHub struct {
	mu   sync.Mutex
	subs map[int64]map[chan agent.LiveEvent]struct{}
}

func newConvHub() *convHub {
	return &convHub{subs: map[int64]map[chan agent.LiveEvent]struct{}{}}
}

// sub registers a new subscriber channel for a conversation. The channel is
// buffered so a brief UI stall can't block the agent; pub drops events when it is
// full (the authoritative text still lands via the persisted Activity on flush).
func (h *convHub) sub(id int64) chan agent.LiveEvent {
	ch := make(chan agent.LiveEvent, 256)
	h.mu.Lock()
	if h.subs[id] == nil {
		h.subs[id] = map[chan agent.LiveEvent]struct{}{}
	}
	h.subs[id][ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *convHub) unsub(id int64, ch chan agent.LiveEvent) {
	h.mu.Lock()
	if m := h.subs[id]; m != nil {
		delete(m, ch)
		if len(m) == 0 {
			delete(h.subs, id)
		}
	}
	h.mu.Unlock()
	close(ch)
}

// pub fans an event out to every subscriber of a conversation, non-blocking.
func (h *convHub) pub(id int64, ev agent.LiveEvent) {
	h.mu.Lock()
	for ch := range h.subs[id] {
		select {
		case ch <- ev:
		default: // slow client — drop rather than block the agent goroutine
		}
	}
	h.mu.Unlock()
}

// pgConversationStream is an SSE endpoint streaming ephemeral live-typing events
// for one conversation. EventSource authenticates with the antifox_token cookie
// (same-origin) like every other API route; the stream stays open until the
// client disconnects and carries only un-persisted deltas + flush markers.
func (s *Server) pgConversationStream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // ask any proxy not to buffer the stream

	ch := s.convHub.sub(id)
	defer s.convHub.unsub(id, ch)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n") // keepalive comment line
			flusher.Flush()
		}
	}
}
