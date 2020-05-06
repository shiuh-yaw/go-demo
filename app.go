package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/go-resty/resty"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	secretKey          string = "sk_test_dfa94177-998c-4781-aa04-970d47df6585"
	publicKey          string = "pk_test_8a3d22b3-5684-4c25-9b21-1fa98776225c"
	baseURL            string = "https://api.sandbox.checkout.com/"
	paymentPath        string = "payments"
	tokensPath         string = "tokens"
	contentType        string = "application/json"
	port               string = "8080"
	cardToken          string = "cko-card-token"
	authKey            string = "Authorization"
	post               string = "POST"
	sessionIDKey       string = "cko-session-id"
	requestTimeout            = 30 * time.Second
	cardVerifiedAmount        = 0
	amount                    = 25
	email              string = "shiuhyaw.phang@checkout.com"
	name               string = "Shiuh Yaw Phang"
	reference          string = "Order Testing - A123456"
	currency           string = "SGD"
	tokenType          string = "token"
	applePayType       string = "applepay"
	googlePayType      string = "googlepay"
	certPem            string = "certificates/certificate.pem"
	certKey            string = "certificates/certificate.key"
	merchantIdentifier string = "merchant.test.sandbox.checkout.com"
	domainName         string = "2489c792.ngrok.io"
	displayName        string = "Checkout Demo Store"
	successHTML        string = "success.html"
	errorHTML          string = "error.html"

	client *resty.Client
)

type (
	// Resp ...
	Resp struct {
		ID              string   `json:"id"`
		ActionID        string   `json:"action_id"`
		Amount          int      `json:"amount"`
		Currency        string   `json:"currency"`
		Approved        bool     `json:"approved"`
		Status          string   `json:"status"`
		AuthCode        string   `json:"auth_code"`
		ResponseCode    string   `json:"response_code"`
		ResponseSummary string   `json:"response_summary"`
		ProcessedOn     string   `json:"processed_on"`
		Reference       string   `json:"reference"`
		Risk            Risk     `json:"risk"`
		Source          Source   `json:"source"`
		Customer        Customer `json:"customer"`
		Links           Links    `json:"_links"`
	}
	// Risk ...
	Risk struct {
		Flagged bool `json:"flagged"`
	}
	// Source ...
	Source struct {
		ID            string `json:"id"`
		Type          string `json:"type"`
		ExpiryMonth   int    `json:"expiry_month"`
		ExpiryYear    int    `json:"expiry_year"`
		Scheme        string `json:"scheme"`
		Last4         string `json:"last4"`
		Fingerprint   string `json:"fingerprint"`
		Bin           string `json:"bin"`
		CardType      string `json:"card_type"`
		CardCategory  string `json:"card_category"`
		Issuer        string `json:"issuer"`
		IssuerCountry string `json:"issuer_country"`
		ProductID     string `json:"product_id"`
		ProductType   string `json:"product_type"`
	}
	// Customer ...
	Customer struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	// Links ...
	Links struct {
		Current     URL `json:"self"`
		RedirectURL URL `json:"redirect"`
	}
	// URL ...
	URL struct {
		URLString string `json:"href"`
	}
	// Error ...
	Error struct {
		/* variables */
	}
	// sessionRequest is the JSON payload sent to Apple for Apple Pay
	// session requests
	sessionRequest struct {
		MerchantIdentifier string `json:"merchantIdentifier"`
		DomainName         string `json:"domainName"`
		DisplayName        string `json:"displayName"`
	}

	// ValidateResponse ...
	ValidateResponse struct {
		DisplayName               string `json:"displayName"`
		DomainName                string `json:"domainName"`
		EpochTimestamp            int    `json:"epochTimestamp"`
		ExpiresAt                 int    `json:"expiresAt"`
		MerchantIdentifier        string `json:"merchantIdentifier"`
		MerchantSessionIdentifier string `json:"merchantSessionIdentifier"`
		Nonce                     string `json:"nonce"`
		Signature                 string `json:"signature"`
	}
	// PaymentToken ...
	PaymentToken struct {
		Token         string `json:"token"`
		Type          string `json:"type"`
		ExpiresOn     string `json:"expires_on"`
		ExpiryMonth   int    `json:"expiry_month"`
		ExpiryYear    int    `json:"expiry_year"`
		Scheme        string `json:"scheme"`
		Last4         string `json:"last4"`
		Fingerprint   string `json:"fingerprint"`
		Bin           string `json:"bin"`
		CardType      string `json:"card_type"`
		CardCategory  string `json:"card_category"`
		Issuer        string `json:"issuer"`
		IssuerCountry string `json:"issuer_country"`
		ProductID     string `json:"product_id"`
		ProductType   string `json:"product_type"`
	}
)

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
	// GoogleResponse ...
	GoogleResponse struct {
		Signature       string
		ProtocolVersion string
		SignedMessage   string
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

const (
	// Pending ...
	Pending string = "Pending"
	// Authorized ...
	Authorized string = "Authorized"
	// Declined ...
	Declined string = "Declined"
	// CardVerified ...
	CardVerified string = "Card Verified"
)

func init() {

	client = resty.New()
	client.SetDebug(true)
	client.SetTimeout(requestTimeout)
	log.Println("Apple Pay test app starting")
}

func main() {

	r := gin.Default()
	r.StaticFile("/", "./static/index.html")
	r.Static("/.well-known", "./static/.well-known")
	r.Static("/images", "./static/images")
	r.Static("/public", "./static")
	r.POST("/getApplePaySession", getApplePaySession)
	r.POST("/processApplePayResponse", processApplePayResponse)
	r.POST("/processGooglePayResponse", processGooglePayResponse)
	r.POST("/", requestCardPayment)
	r.GET("/success", successCardPayment)
	r.GET("/error", errorCardPayment)
	r.LoadHTMLGlob("./static/templates/*")

	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	r.Run("localhost:" + port)
}

func requestCardPayment(c *gin.Context) {

	token := c.PostForm(cardToken)
	body := map[string]interface{}{
		"source": map[string]string{
			"type":  tokenType,
			"token": token,
		},
		"amount":    strconv.Itoa(amount * 100),
		"currency":  currency,
		"reference": reference,
		"3ds": map[string]bool{
			"enabled":     true,
			"attempt_n3d": true,
		},
		"customer": map[string]string{
			"email": email,
			"name":  name,
		},
	}
	resp, err := client.R().
		SetHeader(authKey, secretKey).
		SetBody(body).
		SetResult(Resp{}).
		SetError(Error{}).
		Post(baseURL + paymentPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	showHTMLPage(resp.Result().(*Resp), c)
}

func successCardPayment(c *gin.Context) {

	path := c.FullPath()
	log.Println(path)
	if path != "/success" {
		c.Status(http.StatusBadRequest)
		return
	}
	sessionID, exist := c.GetQuery(sessionIDKey)
	if !exist {
		c.Status(http.StatusBadRequest)
		return
	}
	if len(sessionID) < 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	resp, err := client.R().
		SetHeader(authKey, secretKey).
		SetResult(Resp{}).
		SetError(Error{}).
		Get(baseURL + paymentPath + "/" + sessionID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	showHTMLPage(resp.Result().(*Resp), c)
}

func errorCardPayment(c *gin.Context) {
	r := &struct{ URL string }{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}
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
	cert, err := tls.LoadX509KeyPair(certPem, certKey)
	if err != nil {
		log.Fatalf("ERROR client certificate: %s", err)
	}
	client.SetCertificates(cert)
	payload, err := client.R().
		SetBody(sessionRequest{
			MerchantIdentifier: merchantIdentifier,
			DomainName:         domainName,
			DisplayName:        displayName,
		}).
		SetResult(ValidateResponse{}).
		SetError(Error{}).
		Post(r.URL)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
	c.Writer.Write(payload.Body())
}

func processApplePayResponse(c *gin.Context) {
	r := &Response{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}
	body := map[string]interface{}{
		"type":       applePayType,
		"token_data": r.Token.PaymentData,
	}
	resp, err := client.R().
		SetHeader(authKey, publicKey).
		SetBody(body).
		SetResult(PaymentToken{}).
		SetError(Error{}).
		Post(baseURL + tokensPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	requestApplePayment(resp.Result().(*PaymentToken), c)
}

func requestApplePayment(t *PaymentToken, c *gin.Context) {

	body := map[string]interface{}{
		"source": map[string]string{
			"type":  tokenType,
			"token": t.Token,
		},
		"amount":    strconv.Itoa(cardVerifiedAmount),
		"currency":  currency,
		"reference": "ApplePay " + reference,
		"customer": map[string]string{
			"email": email,
			"name":  name,
		},
	}
	resp, err := client.R().
		SetHeader(authKey, secretKey).
		SetBody(body).
		SetResult(Resp{}).
		SetError(Error{}).
		Post(baseURL + paymentPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	showHTMLPage(resp.Result().(*Resp), c)
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

func processGooglePayResponse(c *gin.Context) {
	r := &GoogleResponse{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}
	body := map[string]interface{}{
		"type":       googlePayType,
		"token_data": r,
	}
	resp, err := client.R().
		SetHeader(authKey, publicKey).
		SetBody(body).
		SetResult(PaymentToken{}).
		SetError(Error{}).
		Post(baseURL + tokensPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	fmt.Println(resp.Result().(*PaymentToken))
	requestGooglePayment(resp.Result().(*PaymentToken), c)
}

func requestGooglePayment(t *PaymentToken, c *gin.Context) {

	body := map[string]interface{}{
		"source": map[string]string{
			"type":  tokenType,
			"token": t.Token,
		},
		"amount":    strconv.Itoa(cardVerifiedAmount),
		"currency":  currency,
		"reference": "GooglePay " + reference,
		"customer": map[string]string{
			"email": email,
			"name":  name,
		},
	}
	resp, err := client.R().
		SetHeader(authKey, secretKey).
		SetBody(body).
		SetResult(Resp{}).
		SetError(Error{}).
		Post(baseURL + paymentPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	showHTMLPage(resp.Result().(*Resp), c)
}

func showHTMLPage(resp *Resp, c *gin.Context) {

	fmt.Println(resp)
	switch resp.Status {
	case Pending:
		c.Redirect(http.StatusMovedPermanently, resp.Links.RedirectURL.URLString)
		c.Abort()
		return
	case Declined:
		c.HTML(http.StatusOK, errorHTML, resp)
		return
	case CardVerified:
		c.HTML(http.StatusOK, successHTML, resp)
		return
	default:
		c.HTML(http.StatusOK, successHTML, resp)
		return
	}
}
