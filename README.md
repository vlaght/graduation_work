# noise with GOST

This is a clone of Go package that implements the [Noise Protocol
Framework](https://noiseprotocol.org). See [the
documentation](https://godoc.org/github.com/flynn/noise) for usage information. In this fork Noise protocol uses ciphersuits based on Russian GOST cryptographic primitives (ГОСТ Р 34.12-2015 with GCM mode and ГОСТ Р 34.11-2012 with 256 and 512 hash length).

# usage
```go
import (
	"github.com/vlaght/noisegost"
)

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func main(){
 	cs := noisegost.NewCipherSuite(noisegost.DH25519, noisegost.CipherKuznechik, noisegost.HashStreebog256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	 hsI, _ := noisegost.NewHandshakeState(noisegost.Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       noisegost.HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := noisegost.NewHandshakeState(noisegost.Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       noisegost.HandshakeXX,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	res, _, _, err := hsR.ReadMessage(nil, msg)

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	res, _, _, err = hsI.ReadMessage(nil, msg)

}
```

TODO:
 - build VPN-tunnel based on this Noise protocol implementation


