package bls

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	cryptobyte_asn1 "golang_org/x/crypto/cryptobyte/asn1"
)

type validity struct {
	NotBefore, NotAfter time.Time
}
type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
)

type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	ECDSA
)

var publicKeyAlgoName = [...]string{
	RSA:   "RSA",
	DSA:   "DSA",
	ECDSA: "ECDSA",
}
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning
)
// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	BasicConstraintsValid bool // if true then the next two fields are valid.
	IsCA                  bool
	MaxPathLen            int
	// MaxPathLenZero indicates that BasicConstraintsValid==true and
	// MaxPathLen==0 should be interpreted as an actual maximum path length
	// of zero. Otherwise, that combination is interpreted as MaxPathLen
	// not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}


var emptyASN1Subject = []byte{0x30, 0}
var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}
var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)
const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)



func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}
func isIA5String(s string) error {
	for _, r := range s {
		if r >= utf8.RuneSelf {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}
func buildExtensions(template *Certificate, subjectIsEmpty bool, authorityKeyId []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionKeyUsage
		ret[n].Critical = true

		var a [2]byte
		a[0] = reverseBitsInAByte(byte(template.KeyUsage))
		a[1] = reverseBitsInAByte(byte(template.KeyUsage >> 8))

		l := 1
		if a[1] != 0 {
			l = 2
		}

		bitString := a[:l]
		ret[n].Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionExtendedKeyUsage

		var oids []asn1.ObjectIdentifier
		for _, u := range template.ExtKeyUsage {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				panic("internal error")
			}
		}

		oids = append(oids, template.UnknownExtKeyUsage...)

		ret[n].Value, err = asn1.Marshal(oids)
		if err != nil {
			return
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		// Leaving MaxPathLen as zero indicates that no maximum path
		// length is desired, unless MaxPathLenZero is set. A value of
		// -1 causes encoding/asn1 to omit the value as desired.
		maxPathLen := template.MaxPathLen
		if maxPathLen == 0 && !template.MaxPathLenZero {
			maxPathLen = -1
		}
		ret[n].Id = oidExtensionBasicConstraints
		ret[n].Value, err = asn1.Marshal(basicConstraints{template.IsCA, maxPathLen})
		ret[n].Critical = true
		if err != nil {
			return
		}
		n++
	}

	if len(template.SubjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(template.SubjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCertificatePolicies
		policies := make([]policyInformation, len(template.PolicyIdentifiers))
		for i, policy := range template.PolicyIdentifiers {
			policies[i].Policy = policy
		}
		ret[n].Value, err = asn1.Marshal(policies)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func CreateCertificate(rand io.Reader, template *Certificate, parent *Certificate, pub *PublicKey, priv interface{}) (cert []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	hashFunc := crypto.SHA256
	var signatureAlgorithm  pkix.AlgorithmIdentifier
	signatureAlgorithm.Algorithm=asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	signatureAlgorithm.Parameters=asn1.NullRawValue

	publicKeyBytes,err :=pub.Bytes()

	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyAlgorithm.Algorithm=asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	publicKeyAlgorithm.Parameters=asn1.NullRawValue

	if err != nil {
		return nil, err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId)
	if err != nil {
		return
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return
	}

	c.Raw = tbsCertContents

	h := hashFunc.New()
	h.Write(tbsCertContents)
	digest := h.Sum(nil)

	var signerOpts crypto.SignerOpts
	signerOpts = hashFunc

	var signature []byte
	signature, err = key.Sign(rand, digest, signerOpts)
	if err != nil {
		return
	}

	return asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}


func parseSANExtension(value []byte) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		switch tag {
		case nameTypeEmail:
			emailAddresses = append(emailAddresses, string(data))
		case nameTypeDNS:
			dnsNames = append(dnsNames, string(data))
		case nameTypeURI:
			uri, err := url.Parse(string(data))
			if err != nil {
				return fmt.Errorf("x509: cannot parse URI %q: %s", string(data), err)
			}
			if len(uri.Host) > 0 {
				if _, ok := domainToReverseLabels(uri.Host); !ok {
					return fmt.Errorf("x509: cannot parse URI %q: invalid domain", string(data))
				}
			}
			uris = append(uris, uri)
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))
			}
		}

		return nil
	})

	return
}
func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := cryptobyte.String(e.Value)
	var toplevel, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
				emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
				ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
				uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain
					// itself, but that's not valid in a
					// normal domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				} else {
					// Otherwise it's a domain name.
					domain := constraint
					if len(domain) > 0 && domain[0] == '.' {
						domain = domain[1:]
					}
					if _, ok := domainToReverseLabels(domain); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain itself,
					// but that's not valid in a normal
					// domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	var cert certificate
	rest, err := asn1.Unmarshal(asn1Data, &cert)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificate(&cert)
}

const BLS = 8
const SHA256withBLS  = 19
func parseCertificate(in *certificate) (*Certificate, error) {
	out := new(Certificate)
	out.Raw = in.Raw
	out.RawTBSCertificate = in.TBSCertificate.Raw
	out.RawSubjectPublicKeyInfo = in.TBSCertificate.PublicKey.Raw
	out.RawSubject = in.TBSCertificate.Subject.FullBytes
	out.RawIssuer = in.TBSCertificate.Issuer.FullBytes

	out.Signature = in.SignatureValue.Bytes
	out.SignatureAlgorithm = SHA256withBLS
	out.PublicKeyAlgorithm = BLS
	var err error
	out.PublicKey, err = PubKeyFromBytes(in.TBSCertificate.PublicKey.PublicKey.Bytes)

	if err != nil {
		return nil, err
	}

	out.Version = in.TBSCertificate.Version + 1
	out.SerialNumber = in.TBSCertificate.SerialNumber

	var issuer, subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCertificate.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 subject")
	}
	if rest, err := asn1.Unmarshal(in.TBSCertificate.Issuer.FullBytes, &issuer); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 subject")
	}

	out.Issuer.FillFromRDNSequence(&issuer)
	out.Subject.FillFromRDNSequence(&subject)

	out.NotBefore = in.TBSCertificate.Validity.NotBefore
	out.NotAfter = in.TBSCertificate.Validity.NotAfter

	for _, e := range in.TBSCertificate.Extensions {
		out.Extensions = append(out.Extensions, e)
		unhandled := false

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				// RFC 5280, 4.2.1.3
				var usageBits asn1.BitString
				if rest, err := asn1.Unmarshal(e.Value, &usageBits); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 KeyUsage")
				}

				var usage int
				for i := 0; i < 9; i++ {
					if usageBits.At(i) != 0 {
						usage |= 1 << uint(i)
					}
				}
				out.KeyUsage = KeyUsage(usage)

			case 19:
				// RFC 5280, 4.2.1.9
				var constraints basicConstraints
				if rest, err := asn1.Unmarshal(e.Value, &constraints); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 BasicConstraints")
				}

				out.BasicConstraintsValid = true
				out.IsCA = constraints.IsCA
				out.MaxPathLen = constraints.MaxPathLen
				out.MaxPathLenZero = out.MaxPathLen == 0
				// TODO: map out.MaxPathLen to 0 if it has the -1 default value? (Issue 19285)
			case 17:
				out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.DNSNames) == 0 && len(out.EmailAddresses) == 0 && len(out.IPAddresses) == 0 && len(out.URIs) == 0 {
					// If we didn't parse anything then we do the critical check, below.
					unhandled = true
				}

			case 30:
				unhandled, err = parseNameConstraintsExtension(out, e)
				if err != nil {
					return nil, err
				}

			case 31:
				// RFC 5280, 4.2.1.13

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

				var cdp []distributionPoint
				if rest, err := asn1.Unmarshal(e.Value, &cdp); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 CRL distribution point")
				}

				for _, dp := range cdp {
					// Per RFC 5280, 4.2.1.13, one of distributionPoint or cRLIssuer may be empty.
					if len(dp.DistributionPoint.FullName) == 0 {
						continue
					}

					for _, fullName := range dp.DistributionPoint.FullName {
						if fullName.Tag == 6 {
							out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(fullName.Bytes))
						}
					}
				}

			case 35:
				// RFC 5280, 4.2.1.1
				var a authKeyId
				if rest, err := asn1.Unmarshal(e.Value, &a); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 authority key-id")
				}
				out.AuthorityKeyId = a.Id

			case 37:
				// RFC 5280, 4.2.1.12.  Extended Key Usage

				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER

				var keyUsage []asn1.ObjectIdentifier
				if rest, err := asn1.Unmarshal(e.Value, &keyUsage); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 ExtendedKeyUsage")
				}

				for _, u := range keyUsage {
					if extKeyUsage, ok := extKeyUsageFromOID(u); ok {
						out.ExtKeyUsage = append(out.ExtKeyUsage, extKeyUsage)
					} else {
						out.UnknownExtKeyUsage = append(out.UnknownExtKeyUsage, u)
					}
				}

			case 14:
				// RFC 5280, 4.2.1.2
				var keyid []byte
				if rest, err := asn1.Unmarshal(e.Value, &keyid); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 key-id")
				}
				out.SubjectKeyId = keyid

			case 32:
				// RFC 5280 4.2.1.4: Certificate Policies
				var policies []policyInformation
				if rest, err := asn1.Unmarshal(e.Value, &policies); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 certificate policies")
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, len(policies))
				for i, policy := range policies {
					out.PolicyIdentifiers[i] = policy.Policy
				}

			default:
				// Unknown extensions are recorded if critical.
				unhandled = true
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			var aia []authorityInfoAccess
			if rest, err := asn1.Unmarshal(e.Value, &aia); err != nil {
				return nil, err
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 authority information")
			}

			for _, v := range aia {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if v.Location.Tag != 6 {
					continue
				}
				if v.Method.Equal(oidAuthorityInfoAccessOcsp) {
					out.OCSPServer = append(out.OCSPServer, string(v.Location.Bytes))
				} else if v.Method.Equal(oidAuthorityInfoAccessIssuers) {
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(v.Location.Bytes))
				}
			}
		} else {
			// Unknown extensions are recorded if critical.
			unhandled = true
		}

		if e.Critical && unhandled {
			out.UnhandledCriticalExtensions = append(out.UnhandledCriticalExtensions, e.Id)
		}
	}

	return out, nil
}
