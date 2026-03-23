// Copyright Contributors to the Open Cluster Management project
package certchains

import (
	"github.com/openshift/library-go/pkg/crypto"
	"time"
)

func NewCAInfo() *CAInfo {
	return &CAInfo{
		signerName:   "",
		validityDays: 365 * 24 * time.Hour, // default to 1 year
		certFile:     "",
		keyFile:      "",
		serialFile:   "",
	}
}

type CAInfo struct {
	signerName   string
	validityDays time.Duration
	certFile     string
	keyFile      string
	serialFile   string
}

func (i *CAInfo) SetSignerName(name string) *CAInfo {
	i.signerName = name
	return i
}
func (i *CAInfo) SetValidityDays(duration time.Duration) *CAInfo {
	i.validityDays = duration
	return i
}
func (i *CAInfo) SetCertFile(file string) *CAInfo {
	i.certFile = file
	return i
}
func (i *CAInfo) SetKeyFile(file string) *CAInfo {
	i.keyFile = file
	return i
}
func (i *CAInfo) SetSerialFile(file string) *CAInfo {
	i.serialFile = file
	return i
}

func (i *CAInfo) EnsureCA() (ca *crypto.CA, err error) {
	ca, _, err = crypto.EnsureCA(
		i.certFile,
		i.keyFile,
		i.serialFile,
		i.signerName,
		i.validityDays,
	)
	return
}
