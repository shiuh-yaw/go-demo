package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

var (
	secretKey          string = "sk_test_dfa94177-998c-4781-aa04-970d47df6585"
	publicKey          string = "pk_test_8a3d22b3-5684-4c25-9b21-1fa98776225c"
	baseURL            string = "https://api.sandbox.checkout.com/"
	gateURL            string = "http://sb-gateway-internal.cko.lon"
	successURL         string = "https://evening-reef-89950.herokuapp.com/success"
	failureURL         string = "https://evening-reef-89950.herokuapp.com/error"
	identityPath       string = "/merchant-identity/identity"
	paymentPath        string = "payments"
	tokensPath         string = "tokens"
	contentType        string = "application/json"
	port               string = "8080"
	cardToken          string = "cko-card-token"
	cartToken          string = "cko-cart-token"
	authKey            string = "Authorization"
	post               string = "POST"
	sessionIDKey       string = "cko-session-id"
	requestTimeout            = 30 * time.Second
	cardVerifiedAmount        = 0
	amount                    = 25
	email              string = "shiuhyaw.phang@checkout.com"
	name               string = "Shiuh Yaw Phang"
	reference          string = "Order Reference"
	currency           string = "SGD"
	tokenType          string = "token"
	applePayType       string = "applepay"
	googlePayType      string = "googlepay"
	certPem            string = "certificates/certificate.pem"
	certKey            string = "certificates/certificate.key"
	merchantIdentifier string = "merchant.test.sandbox.checkout.com"
	domainName         string = "evening-reef-89950.herokuapp.com"
	displayName        string = "Checkout Demo Store"
	successHTML        string = "success.html"
	errorHTML          string = "error.html"
	paymentType        string = "regular"
	description        string = "Transaction description"
	client             *resty.Client
)

type (
	// Resp ...
	Resp struct {
		ID              string    `json:"id"`
		ActionID        string    `json:"action_id"`
		Amount          int       `json:"amount"`
		Currency        string    `json:"currency"`
		Approved        bool      `json:"approved"`
		Status          string    `json:"status"`
		AuthCode        string    `json:"auth_code"`
		ResponseCode    string    `json:"response_code"`
		ResponseSummary string    `json:"response_summary"`
		ProcessedOn     string    `json:"processed_on"`
		Reference       string    `json:"reference"`
		Risk            *Risk     `json:"risk"`
		Source          *Source   `json:"source"`
		Customer        *Customer `json:"customer"`
		Links           *Links    `json:"_links"`
		JSON            string    `json:"json"`
	}
	// Risk ...
	Risk struct {
		Flagged bool `json:"flagged,omitempty"`
		Enabled bool `json:"enabled" binding:"required"`
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
		Type     *string `json:"type,omitempty"`
		ID       string  `json:"id,omitempty"`
		Email    string  `json:"email,omitempty"`
		Name     string  `json:"name,omitempty"`
		Document string  `json:"document,omitempty"`
	}
	// Links ...
	Links struct {
		Current     *URL `json:"self"`
		RedirectURL *URL `json:"redirect"`
	}
	// URL ...
	URL struct {
		URLString string `json:"href"`
	}
	// Error ...
	Error struct {
		/* variables */
		Message string `json:"message"`
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
		ShippingContact *Contact
		BillingContact  *Contact
		Token           *PKPaymentToken
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
		PaymentMethod         *PaymentMethod
		PaymentData           *PaymentData
	}
	// PaymentMethod ...
	PaymentMethod struct {
		Type        string
		Network     string
		DisplayName string
	}
	// PaymentData ...
	PaymentData struct {
		// Apple Pay
		Version *string `json:"version,omitempty"`
		// Apple Pay & Google Pay
		Signature []byte `json:"signature,omitempty"`
		// Apple Pay
		Header *Header `json:"header,omitempty"`
		// Apple Pay
		Data *[]byte `json:"data,omitempty"`
		// Google Pay
		ProtocolVersion *string `json:"protocolVersion,omitempty"`
		// Google Pay
		SignedMessage *string `json:"signedMessage,omitempty"`
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

type (
	// MerchantKey ...
	MerchantKey struct {
		SK string `json:"sk_key"`
		PK string `json:"pb_key"`
	}

	// Payment ...
	Payment struct {
		Source            interface{}        `json:"source"`
		Amount            int                `json:"amount,omitempty"`
		Currency          string             `json:"currency" binding:"required"`
		Reference         string             `json:"reference,omitempty"`
		PaymentType       string             `json:"payment_type,omitempty"`
		Description       string             `json:"description,omitempty"`
		Capture           bool               `json:"capture,omitempty"`
		CaptureOn         string             `json:"capture_on,omitempty"`
		Customer          *Customer          `json:"customer,omitempty"`
		BillingDescriptor *BillingDescriptor `json:"billing_descriptor,omitempty"`
		Shipping          *Shipping          `json:"shipping,omitempty"`
		ThreeDS           *ThreeDS           `json:"3ds,omitempty"`
		PreviousPaymentID string             `json:"previous_payment_id,omitempty"`
		Risk              *Risk              `json:"risk,omitempty"`
		SuccessURL        string             `json:"success_url,omitempty"`
		FailureURL        string             `json:"failure_url,omitempty"`
		PaymentIP         string             `json:"payment_ip,omitempty"`
		Recipient         *Recipient         `json:"recipient,omitempty"`
		Processing        *Processing        `json:"processing,omitempty"`
		Metadata          *Metadata          `json:"metadata,omitempty"`
	}
	// Poli ...
	Poli struct {
		Type string `json:"type" binding:"required"`
	}

	// AliPay ...
	AliPay struct {
		Type string `json:"type" binding:"required"`
	}
	// PayPal ...
	PayPal struct {
		Type          string `json:"type" binding:"required"`
		InvoiceNumber string `json:"invoice_number" binding:"required"`
		RecipientName string `json:"recipient_name,omitempty"`
		LogoURL       string `json:"logo_url,omitempty"`
		STC           *STC   `json:"stc,omitempty"`
	}

	// NetworkToken ...
	NetworkToken struct {
		Type           string   `json:"type" binding:"required"`
		Token          string   `json:"token" binding:"required"`
		ExpiryMonth    int      `json:"expiry_month" binding:"required"`
		ExpiryYear     int      `json:"expiry_year" binding:"required"`
		TokenType      string   `json:"token_type" binding:"required"`
		Cryptogram     string   `json:"cryptogram" binding:"required"`
		ECI            string   `json:"eci" binding:"required"`
		Stored         bool     `json:"stored,omitempty"`
		Name           string   `json:"name,omitempty"`
		CVV            string   `json:"cvv,omitempty"`
		BillingAddress *Address `json:"billing_address,omitempty"`
		Phone          *Phone   `json:"phone,omitempty"`
	}

	// Card ...
	Card struct {
		Type           string   `json:"type" binding:"required"`
		Number         string   `json:"number" binding:"required"`
		ExpiryMonth    int      `json:"expiry_month" binding:"required"`
		ExpiryYear     int      `json:"expiry_year" binding:"required"`
		Name           string   `json:"name,omitempty"`
		CVV            string   `json:"cvv,omitempty"`
		Stored         bool     `json:"stored,omitempty"`
		BillingAddress *Address `json:"billing_address,omitempty"`
		Phone          *Phone   `json:"phone,omitempty"`
	}

	// PaymentSource ...
	PaymentSource struct {
		Type string `json:"type" binding:"required"`
		ID   string `json:"id" binding:"required"`
		CVV  string `json:"cvv,omitempty"`
	}
	// CardToken ...
	CardToken struct {
		Type           string   `json:"type" binding:"required"`
		Token          string   `json:"token,omitempty" binding:"required"`
		Number         string   `json:"number" binding:"required"`
		ExpiryMonth    int      `json:"expiry_month" binding:"required"`
		ExpiryYear     int      `json:"expiry_year" binding:"required"`
		Name           string   `json:"name,omitempty"`
		CVV            string   `json:"cvv,omitempty"`
		BillingAddress *Address `json:"billing_address,omitempty"`
		Phone          *Phone   `json:"phone,omitempty"`
		InvoiceNumber  string   `json:"invoice_number,omitempty"`
	}
	// WalletToken ...
	WalletToken struct {
		Type      string       `json:"type" binding:"required"`
		TokenData *PaymentData `json:"token_data,omitempty"`
	}
	// ThreeDS - Information required for 3D Secure payments
	ThreeDS struct {
		Enabled    bool `json:"enabled,omitempty"`
		AttemptN3d bool `json:"attempt_n3d,omitempty"`
		ECI        bool `json:"eci,omitempty"`
		Cryptogram bool `json:"cryptogram,omitempty"`
		XID        bool `json:"xid,omitempty"`
		Version    bool `json:"version,omitempty"`
	}
	// Address ...
	Address struct {
		AddressLine1 string `json:"address_line1,omitempty"`
		AddressLine2 string `json:"address_line2,omitempty"`
		City         string `json:"city,omitempty"`
		State        string `json:"state,omitempty"`
		Zip          string `json:"zip,omitempty"`
		Country      string `json:"country,omitempty"`
	}
	// Phone ...
	Phone struct {
		CountryCode string `json:"country_code,omitempty"`
		Number      string `json:"number,omitempty"`
	}
	// STC ...
	STC struct {
		Name string `json:"name,omitempty"`
	}
	// BillingDescriptor ...
	BillingDescriptor struct {
		Name string `json:"name" binding:"required"`
		City string `json:"city" binding:"required"`
	}
	// Shipping ...
	Shipping struct {
		Address Address `json:"address,omitempty"`
		Phone   Phone   `json:"phone,omitempty"`
	}
	// Recipient - Information about the recipient of the payment's funds.
	// Relevant for both Account Funding Transactions and VISA
	// or MasterCard domestic UK transactions processed by Financial Institutions.
	Recipient struct {
		DOB            string `json:"dob,omitempty"`
		AcccountNumber string `json:"account_number,omitempty"`
		Zip            string `json:"zip,omitempty"`
		FirstName      string `json:"first_name,omitempty"`
		LastName       string `json:"last_name,omitempty"`
	}
	// Processing - Use the processing object to influence or
	// override the data sent during card processing
	Processing struct {
		// Overrides the default merchant/acceptor identifier (MID)
		// configured on your account
		Mid string `json:"mid,omitempty"`
		// Indicates whether the payment is an Account Funding Transaction
		Aft    bool    `json:"aft,omitempty"`
		DLocal *DLocal `json:"dlocal,omitempty"`
	}
	// DLocal - Processing information required for dLocal payments.
	DLocal struct {
		Country     string       `json:"country,omitempty"`
		Payer       *Customer    `json:"payer,omitempty"`
		Installment *Installment `json:"installment,omitempty"`
	}
	// Installment - Details about the installments.
	Installment struct {
		Count string `json:"count,omitempty"`
	}
	// Metadata - Allows you to store additional information about a transaction with custom fields
	// and up to five user-defined fields (udf1 to udf5),
	// which can be used for reporting purposes. udf1 is also used for some of our risk rules.
	Metadata struct {
		UDF1 string `json:"udf1,omitempty"`
		UDF2 string `json:"udf2,omitempty"`
		UDF3 string `json:"udf3,omitempty"`
		UDF4 string `json:"udf4,omitempty"`
		UDF5 string `json:"udf5,omitempty"`
	}
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
	r.StaticFile("/", "./static/key.html")
	r.StaticFile("/introduction", "./static/documents.html")
	r.StaticFile("/500", "./static/500-error.html")
	r.StaticFile("/checkout", "./static/checkout-page.html")
	r.StaticFile("/shop", "./static/ecommerce.html")
	r.StaticFile("/404", "./static/404-error.html")
	r.StaticFile("/invoice", "./static/invoice-page.html")
	r.StaticFile("/product", "./static/product-page.html")
	r.StaticFile("/reset", "./static/reset-page.html")

	r.Static("/.well-known", "./static/.well-known")
	r.Static("/images", "./static/images")
	r.Static("/assets", "./static/assets")
	r.Static("/public", "./static")
	r.POST("/getApplePaySession", getApplePaySession)
	r.POST("/processApplePayResponse", processApplePayResponse)
	r.POST("/processGooglePayResponse", processGooglePayResponse)
	r.POST("/", requestCardPayment)
	r.GET("/paypal", requestPayPalPayment)
	r.GET("/alipay", requestAlipayPayment)
	r.GET("/wechatpay", requestWeChatpayPayment)
	r.GET("/enet", requestENetPayment)
	r.GET("/poli", requestPoliPayment)
	r.GET("/success", successCardPayment)
	r.GET("/error", errorCardPayment)
	r.LoadHTMLGlob("./static/templates/*")

	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	r.Run(":" + port)
}

func requestCardPayment(c *gin.Context) {

	token := c.PostForm(cardToken)
	var amount = c.PostForm("amount")
	if len(token) < 1 || len(amount) < 1 {
		publicKey = c.PostForm("pb_key")
		secretKey = c.PostForm("sk_key")
		successURL = c.PostForm("success_url")
		failureURL = c.PostForm("failure_url")
		if len(secretKey) < 1 {
			c.Abort()
			return
		}
		if len(publicKey) < 1 {
			c.Abort()
			return
		}
		if len(successURL) < 1 {
			c.Abort()
			return
		}
		if len(failureURL) < 1 {
			c.Abort()
			return
		}
		var merchantKey = MerchantKey{SK: secretKey, PK: publicKey}
		c.HTML(http.StatusOK, "index.html", merchantKey)
		return
	}
	var randInteger = rand.Intn(100000)
	var randString = strconv.Itoa(randInteger)
	var currency = c.PostForm("currency")
	var source = CardToken{Type: tokenType, Token: token}
	var threeDS = &ThreeDS{Enabled: true, AttemptN3d: true}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randString, UDF2: "USER-123(Internal ID)"}
	var total int = 0
	var randReference = randString + " - " + reference

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			log.Println(err)
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			log.Println(err)
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}

	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          currency,
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		ThreeDS:           threeDS,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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
	fmt.Println("Response string")
	if resp.Body() == nil {
		c.Status(http.StatusBadRequest)
		return
	}
	fmt.Println(string(resp.Body()))
	var res = resp.Result().(*Resp)
	res.JSON = string(resp.Body())
	showHTMLPage(res, c)
}

func requestPayPalPayment(c *gin.Context) {

	var source = CardToken{Type: "paypal", InvoiceNumber: "PAYPAL - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            amount * 100,
		Currency:          currency,
		PaymentType:       paymentType,
		Reference:         reference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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

func requestAlipayPayment(c *gin.Context) {

	var source = CardToken{Type: "alipay", InvoiceNumber: "ALIPAY - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            amount * 100,
		Currency:          "USD",
		PaymentType:       paymentType,
		Reference:         reference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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

func requestWeChatpayPayment(c *gin.Context) {

	var source = CardToken{Type: "wechatpay", InvoiceNumber: "WECHATPAY - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            amount * 100,
		Currency:          "USD",
		PaymentType:       paymentType,
		Reference:         reference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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

func requestENetPayment(c *gin.Context) {

	var source = CardToken{Type: "enets", InvoiceNumber: "eNETS - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            amount * 100,
		Currency:          "SGD",
		PaymentType:       paymentType,
		Reference:         reference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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

func requestPoliPayment(c *gin.Context) {

	var source = CardToken{Type: "poli", InvoiceNumber: "POLI - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            amount * 100,
		Currency:          "AUD",
		PaymentType:       paymentType,
		Reference:         reference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
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

func errorCardPayment(c *gin.Context) {
	c.HTML(http.StatusOK, errorHTML, Error{Message: "Payment 3DS Authentication failed."})
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
	var body = WalletToken{
		Type:      applePayType,
		TokenData: r.Token.PaymentData,
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

	var source = CardToken{
		Type:  tokenType,
		Token: t.Token,
	}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var body = Payment{
		Source:            source,
		Amount:            cardVerifiedAmount,
		Currency:          currency,
		Reference:         "ApplePay " + reference,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
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
	r := &PaymentData{}
	if err := c.BindJSON(r); err != nil {
		log.Println(err)
		c.Status(http.StatusBadRequest)
		return
	}
	var body = WalletToken{
		Type:      googlePayType,
		TokenData: r,
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

	var source = CardToken{Type: tokenType, Token: t.Token}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var body = Payment{
		Source:            source,
		Amount:            cardVerifiedAmount,
		Currency:          currency,
		Reference:         "GooglePay " + reference,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
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
