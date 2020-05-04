package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	ap *Merchant
)

func init() {

	var err error
	ap, err = New(
		"merchant.test.sandbox.checkout.com",
		MerchantDisplayName("Checkout Demo Store"),
		MerchantDomainName("9ec8632d.ngrok.io"),
		MerchantCertificateLocation(
			"certificates/certificate.pem",
			"certificates/certificate.key",
		),
	)
	if err != nil {
		panic(err)
	}
	log.Println("Apple Pay test app starting")
}

func main() {

	r := gin.Default()
	r.StaticFile("/", "./static/index.html")
	r.Static("/.well-known", "./static/.well-known")
	r.Static("/public", "./static")
	r.POST("/getApplePaySession", getApplePaySession)
	r.POST("/processApplePayResponse", processApplePayResponse)
	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	r.Run("localhost:" + port)
}

func getApplePaySession(c *gin.Context) {
	r := &struct{ URL string }{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}
	if err := checkSessionURL(r.URL); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	payload, err := ap.Session(r.URL)
	if err != nil {
		log.Println(err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Type", "application/json")
	c.Writer.Write(payload)
}

type (
	// sessionRequest is the JSON payload sent to Apple for Apple Pay
	// session requests
	sessionRequest struct {
		MerchantIdentifier string `json:"merchantIdentifier"`
		DomainName         string `json:"domainName"`
		DisplayName        string `json:"displayName"`
	}
)

// Session ...
func (m Merchant) Session(url string) (sessionPayload []byte, err error) {
	if m.merchantCertificate == nil {
		return nil, errors.New("nil merchant certificate")
	}
	// Verify that the session URL is Apple's
	if err := checkSessionURL(url); err != nil {
		return nil, errors.Wrap(err, "invalid session request URL")
	}

	// Send a session request to Apple
	cl := m.authenticatedClient()
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(m.sessionRequest())
	res, err := cl.Post(url, "application/json", buf)
	if err != nil {
		return nil, errors.Wrap(err, "error making the request")
	}

	// Return directly the result
	body, _ := ioutil.ReadAll(res.Body)
	//res.Body.Close()
	return body, nil
}

// checkSessionURL validates the request URL sent by the client to check that it
// belongs to Apple
func checkSessionURL(location string) error {
	u, err := url.Parse(location)
	if err != nil {
		return errors.Wrap(err, "error parsing the URL")
	}
	hostReg := regexp.MustCompile("^apple-pay-gateway(-.+)?.apple.com$")
	if !hostReg.MatchString(u.Host) {
		return errors.New("invalid host")
	}
	if u.Scheme != "https" {
		return errors.New("unsupported protocol")
	}
	return nil
}

// sessionRequest builds a request struct for Apple Pay sessions
func (m Merchant) sessionRequest() *sessionRequest {
	return &sessionRequest{
		MerchantIdentifier: m.identifier,
		DomainName:         m.domainName,
		DisplayName:        m.displayName,
	}
}

// authenticatedClient returns a HTTP client authenticated with the Merchant
// Identity certificate signed by Apple
func (m Merchant) authenticatedClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					*m.merchantCertificate,
				},
			},
		},
		Timeout: requestTimeout,
	}
}

var (
	requestTimeout = 30 * time.Second
)

var (
	// merchantIDHashOID is the ASN.1 object identifier of Apple's extension
	// for merchant ID hash in merchant/processing certificates
	merchantIDHashOID = mustParseASN1ObjectIdentifier(
		"1.2.840.113635.100.6.32",
	)
)

type (
	Merchant struct {
		identifier          string
		displayName         string
		domainName          string
		merchantCertificate *tls.Certificate
	}
)

// New creates an instance of Merchant using the given configuration
func New(merchantID string, options ...func(*Merchant) error) (*Merchant, error) {
	if !strings.HasPrefix(merchantID, "merchant.") {
		return nil, errors.New("merchant ID should start with `merchant.`")
	}

	m := &Merchant{identifier: merchantID}
	for _, option := range options {
		err := option(m)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Merchant) identifierHash() []byte {
	h := sha256.New()
	h.Write([]byte(m.identifier))
	return h.Sum(nil)
}

// MerchantDisplayName ...
func MerchantDisplayName(displayName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.displayName = displayName
		return nil
	}
}

// MerchantDomainName ...
func MerchantDomainName(domainName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.domainName = domainName
		return nil
	}
}

// MerchantCertificate ...
func MerchantCertificate(cert tls.Certificate) func(*Merchant) error {
	return func(m *Merchant) error {
		// Check that the certificate is RSA
		if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
			return errors.New("merchant key should be RSA")
		}
		// Verify merchant ID
		hash, err := extractMerchantHash(cert)
		if err != nil {
			return errors.Wrap(err, "error reading the certificate")
		}
		if !bytes.Equal(hash, m.identifierHash()) {
			return errors.New("invalid merchant certificate or merchant ID")
		}
		m.merchantCertificate = &cert
		return nil
	}
}

// MerchantCertificateLocation ...
func MerchantCertificateLocation(certLocation,
	keyLocation string) func(*Merchant) error {

	return loadCertificate(certLocation, keyLocation, MerchantCertificate)
}

func loadCertificate(certLocation, keyLocation string,
	callback func(tls.Certificate) func(*Merchant) error) func(
	*Merchant) error {

	return func(m *Merchant) error {
		cert, err := tls.LoadX509KeyPair(certLocation, keyLocation)
		if err != nil {
			return errors.Wrap(err, "error loading the certificate")
		}
		return callback(cert)(m)
	}
}

func extractMerchantHash(cert tls.Certificate) ([]byte, error) {
	if cert.Certificate == nil {
		return nil, errors.New("nil certificate")
	}

	// Parse the leaf certificate of the certificate chain
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "certificate parsing error")
	}

	extValue, err := extractExtension(leaf, merchantIDHashOID)
	if err != nil {
		return nil, errors.Wrap(err, "error finding the hash extension")
	}
	// First two bytes are "@."
	if len(extValue) != 66 {
		return nil, errors.New("invalid hash length")
	}
	merchantIDString, err := hex.DecodeString(string(extValue[2:]))
	if err != nil {
		return nil, errors.Wrap(err, "invalid hash hex")
	}
	return []byte(merchantIDString), nil
}

// extractExtension returns the value of a certificate extension if it exists
func extractExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (
	[]byte, error) {

	if cert == nil {
		return nil, errors.New("nil certificate")
	}

	var res []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		res = ext.Value
	}
	if res == nil {
		return nil, errors.New("extension not found")
	}

	return res, nil
}

// mustParseASN1ObjectIdentifier calls parseASN1ObjectIdentifier and panics if
// it returns an error
func mustParseASN1ObjectIdentifier(id string) asn1.ObjectIdentifier {
	oid, err := parseASN1ObjectIdentifier(id)
	if err != nil {
		panic(errors.Wrap(err, "error parsing the OID"))
	}
	return oid
}

// parseASN1ObjectIdentifier parses an ASN.1 object identifier string of the
// form x.x.x.x.x.x.x.x into a Go asn1.ObjectIdentifier
func parseASN1ObjectIdentifier(id string) (asn1.ObjectIdentifier, error) {
	idSplit := strings.Split(id, ".")
	oid := make([]int, len(idSplit))
	for i, str := range idSplit {
		r, err := strconv.Atoi(str)
		if err != nil {
			return nil, errors.Wrapf(err, "error parsing %s", str)
		}
		oid[i] = r
	}
	return oid, nil
}

type (
	// Response is the full response from the user's device after an Apple
	// Pay request
	Response struct {
		ShippingContact Contact
		BillingContact  Contact
		Token           PKPaymentToken
	}

	// Contact is the struct that contains billing/shipping information from an
	// Apple Pay response
	Contact struct {
		GivenName          string
		FamilyName         string
		EmailAddress       string
		AddressLines       []string
		AdministrativeArea string
		Locality           string
		PostalCode         string
		Country            string
		CountryCode        string
	}
)

type (
	// PKPaymentToken is the payment information returned by Apple Pay with
	// all data, and an encrypted token
	// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
	PKPaymentToken struct {
		transactionTime       time.Time
		TransactionIdentifier string
		PaymentMethod         PaymentMethod
		PaymentData           PaymentData
	}
	// PaymentMethod ...
	PaymentMethod struct {
		Type        string
		Network     string
		DisplayName string
	}
	// PaymentData ...
	PaymentData struct {
		Version   string
		Signature []byte
		Header    Header
		Data      []byte
	}
	// Header ...
	Header struct {
		ApplicationData    string
		EphemeralPublicKey []byte
		WrappedKey         []byte
		PublicKeyHash      []byte
		TransactionID      string
	}

	// Token is the decrypted form of Response.Token.PaymentData.Data
	Token struct {
		// ApplicationPrimaryAccountNumber is the device-specific account number of the card that funds this
		// transaction
		ApplicationPrimaryAccountNumber string
		// ApplicationExpirationDate is the card expiration date in the format YYMMDD
		ApplicationExpirationDate string
		// CurrencyCode is the ISO 4217 numeric currency code, as a string to preserve leading zeros
		CurrencyCode string
		// TransactionAmount is the value of the transaction
		TransactionAmount float64
		// CardholderName is the name on the card
		CardholderName string
		// DeviceManufacturerIdentifier is a hex-encoded device manufacturer identifier
		DeviceManufacturerIdentifier string
		// PaymentDataType is either 3DSecure or, if using Apple Pay in China, EMV
		PaymentDataType string
		// PaymentData contains detailed payment data
		PaymentData struct {
			// 3-D Secure fields

			// OnlinePaymentCryptogram is the 3-D Secure cryptogram
			OnlinePaymentCryptogram []byte
			// ECIIndicator is the Electronic Commerce Indicator for the status of 3-D Secure
			ECIIndicator string

			// EMV fields

			// EMVData is the output from the Secure Element
			EMVData []byte
			// EncryptedPINData is the PIN encrypted with the bank's key
			EncryptedPINData string
		}
	}

	// version is used to represent the different versions of encryption used by Apple Pay
	version string
)

func processApplePayResponse(c *gin.Context) {
	r := &Response{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	token, err := ap.DecryptResponse(r)
	if err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}

	fmt.Println("Token received!")
	spew.Dump(token)
	// TODO: check price…
	c.Status(http.StatusOK)
}
