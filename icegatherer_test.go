// +build !js

package webrtc

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/test"
)

func TestNewICEGatherer_Success(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	opts := ICEGatherOptions{
		ICEServers: []ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
	}

	api := NewAPI()

	gatherer, err := api.NewICEGatherer(opts)
	if err != nil {
		t.Error(err)
	}

	if gatherer.State() != ICEGathererStateNew {
		t.Fatalf("Expected gathering state new")
	}

	// err = gatherer.Gather()
	// if err != nil {
	// 	t.Error(err)
	// }

	params, err := gatherer.GetLocalParameters()
	if err != nil {
		t.Error(err)
	}

	if len(params.UsernameFragment) == 0 ||
		len(params.Password) == 0 {
		t.Fatalf("Empty local username or password frag")
	}

	candidates, err := gatherer.GetLocalCandidates()
	if err != nil {
		t.Error(err)
	}

	if len(candidates) == 0 {
		t.Fatalf("No candidates gathered")
	}

	err = gatherer.Close()
	if err != nil {
		t.Error(err)
	}
}

func TestNewICEGatherer_Trickle(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	var wg sync.WaitGroup
	wg.Add(1)

	opts := ICEGatherOptions{
		ICEServers: []ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
		OnCandidate: func(candidate *ICECandidate) {
			if candidate == nil {
				wg.Done()
			}
		},
	}

	settingEngine := SettingEngine{}
	settingEngine.candidates.ICETrickle = true

	api := NewAPI(WithSettingEngine(settingEngine))

	gatherer, err := api.NewICEGatherer(opts)
	if err != nil {
		t.Error(err)
	}

	if gatherer.State() != ICEGathererStateNew {
		t.Fatalf("Expected gathering state new")
	}

	err = gatherer.Gather()
	if err != nil {
		t.Error(err)
	}

	wg.Wait()

	params, err := gatherer.GetLocalParameters()
	if err != nil {
		t.Error(err)
	}

	if len(params.UsernameFragment) == 0 ||
		len(params.Password) == 0 {
		t.Fatalf("Empty local username or password frag")
	}

	candidates, err := gatherer.GetLocalCandidates()
	if err != nil {
		t.Error(err)
	}

	if len(candidates) == 0 {
		t.Fatalf("No candidates gathered")
	}

	err = gatherer.Close()
	if err != nil {
		t.Error(err)
	}
}
