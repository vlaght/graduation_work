package noisegost

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type NoiseSuite struct{}

var _ = Suite(&NoiseSuite{})

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func (NoiseSuite) TestN(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rng,
		Pattern:     HandshakeN,
		Initiator:   true,
		PeerStatic:  staticR.Public,
	})

	hello, _, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254c1179a4e12137cbab72eb0ed29b7008b")
	c.Assert(hello, DeepEquals, expected)
}

func (NoiseSuite) TestX(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})

	hello, _, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a9442fb949290cc2bc347f717c9c224ff7d7860e932a71edc4d5a196eb680674c240f8723d0d528d439582d7b292002a1b16835ba4f27400fbea71888412bea95")
	c.Assert(hello, DeepEquals, expected)
}

func (NoiseSuite) TestNN(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c3024aedc8e58d5b9ade9042ef4eaf62be61e88f7")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestXX(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	msg, _, _, _ = hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("aa035e8112ce1aef09a2fc68fd0167a21ebd295957a8e46b197199747d7939143796e8f0fc72d456ebb4a2a1ea46c82ca1c3fdf358b69ec73dab9a1ae7fca5b3")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestIK(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeIK,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeIK,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 99)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b2aeb69aaafd31cc13efe70ee9278a82dbed77ee1")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestXXRoundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})

	// -> e
	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abcdef"))
	c.Assert(msg, HasLen, 38)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abcdef")

	// <- e, dhee, s, dhse
	msg, _, _, _ = hsR.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 96)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// -> s, dhse
	payload := "0123456789012345678901234567890123456789012345678901234567890123456789"
	msg, csI0, csI1, _ := hsI.WriteMessage(nil, []byte(payload))
	c.Assert(msg, HasLen, 134)
	res, csR0, csR1, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, payload)

	// transport message I -> R
	msg = csI0.Encrypt(nil, nil, []byte("wubba"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "wubba")

	// transport message I -> R again
	msg = csI0.Encrypt(nil, nil, []byte("aleph"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "aleph")

	// transport message R <- I
	msg = csR1.Encrypt(nil, nil, []byte("worri"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "worri")
}

func (NoiseSuite) Test_NNpsk0_Roundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})

	// -> e
	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 48)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// <- e, dhee
	msg, csR0, csR1, _ := hsR.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 48)
	res, csI0, csI1, err := hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// transport I -> R
	msg = csI0.Encrypt(nil, nil, []byte("foo"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "foo")

	// transport R -> I
	msg = csR1.Encrypt(nil, nil, []byte("bar"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "bar")
}

func (NoiseSuite) Test_Npsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rng,
		Pattern:      HandshakeN,
		Initiator:    true,
		PresharedKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		PeerStatic:   staticR.Public,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 48)

	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662543cff577e31f7a9e2ffcfcfd5c6006bb1")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) Test_Xpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)

	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		PresharedKey:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	msg, _, _, _ := hs.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 96)

	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a228d04f423f0f9ba2cb264c6a8823b2a0b57fba746f740f200190d77cd0479019ede95c14e07dd9ee3af700165c2ab07de52316a08e88142e529fb7f82428ba5")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) Test_NNpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		Prologue:     prologue,
		PresharedKey: psk,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		Prologue:     prologue,
		PresharedKey: psk,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c0b4cb5be4c213b386e3f91e709a011e0aa8229bf")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) Test_XXpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	msg, _, _, _ = hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("9a89933d88009ec3eb1abce97ee0a6dc2c657dadb9986b09953af4116a3fe72fd2d165da3b7436cbdd9fd4e4dc3861177a0444081dc30941500494928e0b4f28")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestHandshakeRollback(c *C) {
	cs := NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	prev := msg[1]
	msg[1] = msg[1] + 1
	_, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, Not(IsNil))
	msg[1] = prev
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c3024aedc8e58d5b9ade9042ef4eaf62be61e88f7")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestRekey(c *C) {
	rng := new(RandomInc)

	clientStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	clientConfig := Config{}
	clientConfig.CipherSuite = NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	clientConfig.Random = rng
	clientConfig.Pattern = HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	clientHs, _ := NewHandshakeState(clientConfig)

	serverStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	serverConfig := Config{}
	serverConfig.CipherSuite = NewCipherSuite(DH25519, CipherKuznechik, HashStribog256)
	serverConfig.Random = rng
	serverConfig.Pattern = HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	serverHs, _ := NewHandshakeState(serverConfig)

	clientHsMsg, _, _, _ := clientHs.WriteMessage(nil, nil)
	c.Assert(32, Equals, len(clientHsMsg))

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg)
	c.Assert(err, IsNil)
	c.Assert(0, Equals, len(serverHsResult))

	serverHsMsg, csR0, csR1, _ := serverHs.WriteMessage(nil, nil)
	c.Assert(48, Equals, len(serverHsMsg))

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, serverHsMsg)
	c.Assert(err, IsNil)
	c.Assert(0, Equals, len(clientHsResult))

	clientMessage := []byte("hello")
	msg := csI0.Encrypt(nil, nil, clientMessage)
	res, err := csR0.Decrypt(nil, nil, msg)
	c.Assert(string(clientMessage), Equals, string(res))

	oldK := csI0.k
	csI0.Rekey()
	c.Assert(oldK, Not(Equals), csI0.k)
	csR0.Rekey()

	clientMessage = []byte("hello again")
	msg = csI0.Encrypt(nil, nil, clientMessage)
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(string(clientMessage), Equals, string(res))

	serverMessage := []byte("bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Equals, string(res))

	csR1.Rekey()
	csI1.Rekey()

	serverMessage = []byte("bye bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Equals, string(res))

	// only rekey one side, test for failure
	csR1.Rekey()
	serverMessage = []byte("bye again")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Not(Equals), string(res))
}
