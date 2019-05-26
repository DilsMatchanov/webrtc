package ice

import (
	"net"
	"testing"

	"github.com/pion/ice"
	"github.com/stretchr/testify/assert"
)

func TestCandidate_Convert(t *testing.T) {
	testCases := []struct {
		native Candidate

		expectedType           ice.CandidateType
		expectedNetwork        string
		expectedIP             net.IP
		expectedPort           int
		expectedComponent      uint16
		expectedRelatedAddress *ice.CandidateRelatedAddress
	}{
		{
			Candidate{
				Foundation: "foundation",
				Priority:   128,
				IP:         "1.0.0.1",
				Protocol:   ProtocolUDP,
				Port:       1234,
				Typ:        CandidateTypeHost,
				Component:  1,
			},

			ice.CandidateTypeHost,
			"udp",
			net.ParseIP("1.0.0.1"),
			1234,
			1,
			nil,
		},
		{
			Candidate{
				Foundation:     "foundation",
				Priority:       128,
				IP:             "::1",
				Protocol:       ProtocolUDP,
				Port:           1234,
				Typ:            CandidateTypeSrflx,
				Component:      1,
				RelatedAddress: "1.0.0.1",
				RelatedPort:    4321,
			},

			ice.CandidateTypeServerReflexive,
			"udp",
			net.ParseIP("::1"),
			1234,
			1,
			&ice.CandidateRelatedAddress{
				Address: "1.0.0.1",
				Port:    4321,
			},
		},
		{
			Candidate{
				Foundation:     "foundation",
				Priority:       128,
				IP:             "::1",
				Protocol:       ProtocolUDP,
				Port:           1234,
				Typ:            CandidateTypePrflx,
				Component:      1,
				RelatedAddress: "1.0.0.1",
				RelatedPort:    4321,
			},

			ice.CandidateTypePeerReflexive,
			"udp",
			net.ParseIP("::1"),
			1234,
			1,
			&ice.CandidateRelatedAddress{
				Address: "1.0.0.1",
				Port:    4321,
			},
		},
	}

	for i, testCase := range testCases {
		actualICE, err := testCase.native.toICE()
		assert.Nil(t, err)

		var expectedICE ice.Candidate

		switch testCase.expectedType {
		case ice.CandidateTypeHost:
			expectedICE, err = ice.NewCandidateHost(testCase.expectedNetwork, testCase.expectedIP, testCase.expectedPort, testCase.expectedComponent)
		case ice.CandidateTypeServerReflexive:
			expectedICE, err = ice.NewCandidateServerReflexive(testCase.expectedNetwork, testCase.expectedIP, testCase.expectedPort, testCase.expectedComponent,
				testCase.expectedRelatedAddress.Address, testCase.expectedRelatedAddress.Port)
		case ice.CandidateTypePeerReflexive:
			expectedICE, err = ice.NewCandidatePeerReflexive(testCase.expectedNetwork, testCase.expectedIP, testCase.expectedPort, testCase.expectedComponent,
				testCase.expectedRelatedAddress.Address, testCase.expectedRelatedAddress.Port)
		}

		assert.Nil(t, err)
		assert.Equal(t, expectedICE, actualICE, "testCase: %d ice not equal %v", i, actualICE)
	}
}

func TestConvertTypeFromICE(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		ct, err := convertTypeFromICE(ice.CandidateTypeHost)
		if err != nil {
			t.Fatal("failed coverting ice.CandidateTypeHost")
		}
		if ct != CandidateTypeHost {
			t.Fatal("should be coverted to CandidateTypeHost")
		}
	})
	t.Run("srflx", func(t *testing.T) {
		ct, err := convertTypeFromICE(ice.CandidateTypeServerReflexive)
		if err != nil {
			t.Fatal("failed coverting ice.CandidateTypeServerReflexive")
		}
		if ct != CandidateTypeSrflx {
			t.Fatal("should be coverted to CandidateTypeSrflx")
		}
	})
	t.Run("prflx", func(t *testing.T) {
		ct, err := convertTypeFromICE(ice.CandidateTypePeerReflexive)
		if err != nil {
			t.Fatal("failed coverting ice.CandidateTypePeerReflexive")
		}
		if ct != CandidateTypePrflx {
			t.Fatal("should be coverted to CandidateTypePrflx")
		}
	})
}
