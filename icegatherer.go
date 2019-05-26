// +build !js

package webrtc

import (
	"errors"
	"sync"
	"time"

	"github.com/pion/ice"
	"github.com/pion/logging"
)

// ICEGatherer gathers local host, server reflexive and relay
// candidates, as well as enabling the retrieval of local Interactive
// Connectivity Establishment (ICE) parameters which can be
// exchanged in signaling.
type ICEGatherer struct {
	lock  sync.RWMutex
	state ICEGathererState

	validatedServers []*ice.URL

	agent *ice.Agent

	trickle           bool
	portMin           uint16
	portMax           uint16
	connectionTimeout *time.Duration
	keepaliveInterval *time.Duration
	loggerFactory     logging.LoggerFactory
	networkTypes      []NetworkType
	log               logging.LeveledLogger

	onCandidateHdlr func(candidate *ICECandidate)
}

// NewICEGatherer creates a new NewICEGatherer.
func NewICEGatherer(
	portMin uint16,
	portMax uint16,
	connectionTimeout *time.Duration,
	keepaliveInterval *time.Duration,
	loggerFactory logging.LoggerFactory,
	trickle bool,
	networkTypes []NetworkType,
	opts ICEGatherOptions,
) (*ICEGatherer, error) {
	var validatedServers []*ice.URL
	if len(opts.ICEServers) > 0 {
		for _, server := range opts.ICEServers {
			url, err := server.validate()
			if err != nil {
				return nil, err
			}
			validatedServers = append(validatedServers, url...)
		}
	}

	g := &ICEGatherer{
		state:             ICEGathererStateNew,
		validatedServers:  validatedServers,
		portMin:           portMin,
		portMax:           portMax,
		connectionTimeout: connectionTimeout,
		keepaliveInterval: keepaliveInterval,
		loggerFactory:     loggerFactory,
		trickle:           trickle,
		networkTypes:      networkTypes,
		onCandidateHdlr:   opts.OnCandidate,
		log:               loggerFactory.NewLogger("ice"),
	}

	config := &ice.AgentConfig{
		Urls:              g.validatedServers,
		Trickle:           g.trickle,
		PortMin:           g.portMin,
		PortMax:           g.portMax,
		ConnectionTimeout: g.connectionTimeout,
		KeepaliveInterval: g.keepaliveInterval,
		LoggerFactory:     g.loggerFactory,
	}

	requestedNetworkTypes := g.networkTypes
	if len(requestedNetworkTypes) == 0 {
		requestedNetworkTypes = supportedNetworkTypes
	}

	for _, typ := range requestedNetworkTypes {
		config.NetworkTypes = append(config.NetworkTypes, ice.NetworkType(typ))
	}

	agent, err := ice.NewAgent(config)
	if err != nil {
		return nil, err
	}

	if err := agent.OnCandidate(func(candidate ice.Candidate) {
		g.lock.Lock()
		defer g.lock.Unlock()

		if candidate != nil {
			c, err := newICECandidateFromICE(candidate)
			if err != nil {
				g.log.Warnf("Failed to convert ice.Candidate: %s", err)
				return
			}

			if g.onCandidateHdlr != nil {
				g.onCandidateHdlr(&c)
			}
		} else {
			g.state = ICEGathererStateComplete
			if g.onCandidateHdlr != nil {
				g.onCandidateHdlr(nil)
			}
		}
	}); err != nil {
		return nil, err
	}

	g.agent = agent
	return g, nil
}

// State indicates the current state of the ICE gatherer.
func (g *ICEGatherer) State() ICEGathererState {
	g.lock.RLock()
	defer g.lock.RUnlock()
	return g.state
}

// Gather ICE candidates.
func (g *ICEGatherer) Gather() error {
	g.lock.Lock()
	defer g.lock.Unlock()

	g.state = ICEGathererStateGathering

	requestedNetworkTypes := g.networkTypes
	if len(requestedNetworkTypes) == 0 {
		requestedNetworkTypes = supportedNetworkTypes
	}

	networkTypes := make([]ice.NetworkType, 0)
	for _, typ := range requestedNetworkTypes {
		networkTypes = append(networkTypes, ice.NetworkType(typ))
	}

	return g.agent.GatherCandidates(g.validatedServers, networkTypes)
}

// Close prunes all local candidates, and closes the ports.
func (g *ICEGatherer) Close() error {
	g.lock.Lock()
	defer g.lock.Unlock()

	if g.agent == nil {
		return nil
	}

	err := g.agent.Close()
	if err != nil {
		return err
	}
	g.agent = nil

	return nil
}

// GetLocalParameters returns the ICE parameters of the ICEGatherer.
func (g *ICEGatherer) GetLocalParameters() (ICEParameters, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()
	if g.agent == nil {
		return ICEParameters{}, errors.New("gatherer not started")
	}

	frag, pwd := g.agent.GetLocalUserCredentials()

	return ICEParameters{
		UsernameFragment: frag,
		Password:         pwd,
		ICELite:          false,
	}, nil
}

// GetLocalCandidates returns the sequence of valid local candidates associated with the ICEGatherer.
func (g *ICEGatherer) GetLocalCandidates() ([]ICECandidate, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()

	if g.agent == nil {
		return nil, errors.New("gatherer not started")
	}

	iceCandidates, err := g.agent.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	return newICECandidatesFromICE(iceCandidates)
}
