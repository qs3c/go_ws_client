package e2ewebsocket

type helloMsg struct {
	original           []byte
	vers               uint16
	random             []byte
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	serverName         string

	supportedCurves []CurveID
	supportedPoints []uint8

	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool

	supportedVersions []uint16

	keyShares []keyShare

	pskModes      []uint8
	pskIdentities []pskIdentity
	pskBinders    [][]byte

	// extensions are only populated on the server-side of a handshake
	extensions []uint16
}
