package webrtc

// ICEGatherOptions provides options relating to the gathering of ICE candidates.
type ICEGatherOptions struct {
	ICEServers  []ICEServer
	OnCandidate func(candidate *ICECandidate)
}
