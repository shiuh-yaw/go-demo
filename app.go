package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/db"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"golang.org/x/net/context"

	"google.golang.org/api/option"
)

var (
	secretKey               string = "sk_test_dfa94177-998c-4781-aa04-970d47df6585"
	publicKey               string = "pk_test_8a3d22b3-5684-4c25-9b21-1fa98776225c"
	baseURL                 string = "https://api.sandbox.checkout.com/"
	gateURL                 string = "http://sb-gateway-internal.cko.lon"
	successURL              string = "https://evening-reef-89950.herokuapp.com/success"
	failureURL              string = "https://evening-reef-89950.herokuapp.com/error"
	identityPath            string = "/merchant-identity/identity"
	paymentPath             string = "payments"
	hostedPaymentsPath      string = "hosted-payments"
	eventsPath              string = "events"
	actionPath              string = "actions"
	capturesPath            string = "captures"
	voidPath                string = "voids"
	refundPath              string = "refunds"
	tokensPath              string = "tokens"
	webhooksPath            string = "webhooks"
	disputesPath            string = "disputes"
	filesPath               string = "files"
	eventTypesPath          string = "event-types"
	contentType             string = "application/json"
	port                    string = "8080"
	cardToken               string = "cko-card-token"
	cartToken               string = "cko-cart-token"
	authKey                 string = "Authorization"
	post                    string = "POST"
	sessionIDKey            string = "cko-session-id"
	paymentIDKey            string = "cko-payment-id"
	referenceID             string = "ref-id"
	requestTimeout                 = 30 * time.Second
	cardVerifiedAmount             = 0
	amount                         = 2500
	applePayAmount                 = 1000
	email                   string = "shiuhyaw.phang@checkout.com"
	name                    string = "Shiuh Yaw Phang"
	reference               string = "Ord"
	currency                string = "SGD"
	tokenType               string = "token"
	applePayType            string = "applepay"
	googlePayType           string = "googlepay"
	certPem                 string = "certificates/certificate.pem"
	certKey                 string = "certificates/certificate.key"
	firebaseAccountKey      string = "certificates/cko-go-demo-firebase-adminsdk-abbzl-bcac4254b3.json"
	localFirebaseAccountKey string = "certificates/local-go-demo-firebase-adminsdk-vx5qn-ae38c3a811.json"

	merchantIdentifier string = "merchant.test.sandbox.checkout.com"
	domainName         string = "evening-reef-89950.herokuapp.com"
	displayName        string = "Checkout Demo Store"
	successHTML        string = "success.html"
	klarnaHTML         string = "klarna.html"
	errorHTML          string = "error.html"
	paymentType        string = "regular"
	description        string = "Transaction description"
	databaseURL        string = "https://local-go-demo.firebaseio.com/"
)

var (
	httpclient       *resty.Client
	firebaseDBClient *db.Client
	ctx              = context.Background()
	paymentRef       *db.Ref
	webhooksRef      *db.Ref
	currentPayment   *Resp
	currentEventType string
)

type (
	// Resp ...
	Resp struct {
		ID              string    `json:"id,omitempty"`
		ActionID        string    `json:"action_id,omitempty"`
		Amount          int       `json:"amount,omitempty"`
		Currency        string    `json:"currency,omitempty"`
		Approved        bool      `json:"approved,omitempty"`
		Status          string    `json:"status,omitempty"`
		AuthCode        string    `json:"auth_code,omitempty"`
		ResponseCode    string    `json:"response_code,omitempty"`
		ResponseSummary string    `json:"response_summary,omitempty"`
		ProcessedOn     string    `json:"processed_on,omitempty"`
		Reference       string    `json:"reference,omitempty"`
		Actions         []Action  `json:"actions,omitempty"`
		Risk            *Risk     `json:"risk,omitempty"`
		Source          *Source   `json:"source,omitempty"`
		Customer        *Customer `json:"customer,omitempty"`
		Links           *Links    `json:"_links,omitempty"`
		JSON            string    `json:"json,omitempty"`
		ARN             *string   `json:"arn,omitempty"`
	}
	// Action ...
	Action struct {
		ID              string      `json:"id,omitempty"`
		Type            *string     `json:"type,omitempty"`
		ProcessedOn     *string     `json:"processed_on,omitempty"`
		Approved        bool        `json:"approved,omitempty"`
		Amount          int         `json:"amount,omitempty"`
		ResponseCode    *string     `json:"response_code,omitempty"`
		ResponseSummary *string     `json:"response_summary,omitempty"`
		Reference       *string     `json:"reference,omitempty"`
		Processing      *Processing `json:"processing,omitempty"`
		Metadata        *Metadata   `json:"metadata,omitempty"`
	}

	// Risk ...
	Risk struct {
		Flagged bool `json:"flagged,omitempty"`
		Enabled bool `json:"enabled,omitempty"`
	}
	// Source ...
	Source struct {
		ID            string `json:"id,omitempty"`
		Type          string `json:"type,omitempty"`
		ExpiryMonth   int    `json:"expiry_month,omitempty"`
		ExpiryYear    int    `json:"expiry_year,omitempty"`
		Name          string `json:"name,omitempty"`
		Scheme        string `json:"scheme,omitempty"`
		Last4         string `json:"last4,omitempty"`
		Fingerprint   string `json:"fingerprint,omitempty"`
		Bin           string `json:"bin,omitempty"`
		CardType      string `json:"card_type,omitempty"`
		CardCategory  string `json:"card_category,omitempty"`
		Issuer        string `json:"issuer,omitempty"`
		IssuerCountry string `json:"issuer_country,omitempty"`
		ProductID     string `json:"product_id,omitempty"`
		ProductType   string `json:"product_type,omitempty"`
		AVSCheck      string `json:"avs_check,omitempty"`
		CVVCheck      string `json:"cvv_check,omitempty"`
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
		Capture           *bool              `json:"capture,omitempty"`
		CaptureOn         *string            `json:"capture_on,omitempty"`
		Customer          *Customer          `json:"customer,omitempty"`
		BillingDescriptor *BillingDescriptor `json:"billing_descriptor,omitempty"`
		Shipping          *Shipping          `json:"shipping,omitempty"`
		ThreeDS           *ThreeDS           `json:"3ds,omitempty"`
		PreviousPaymentID string             `json:"previous_payment_id,omitempty"`
		Risk              *Risk              `json:"risk,omitempty"`
		SuccessURL        string             `json:"success_url,omitempty"`
		FailureURL        string             `json:"failure_url,omitempty"`
		CancelURL         string             `json:"cancel_url,omitempty"`
		PaymentIP         string             `json:"payment_ip,omitempty"`
		Billing           *Billing           `json:"billing,omitempty"`
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
		Type              string   `json:"type" binding:"required"`
		Token             string   `json:"token,omitempty" binding:"required"`
		Number            string   `json:"number" binding:"required"`
		ExpiryMonth       int      `json:"expiry_month" binding:"required"`
		ExpiryYear        int      `json:"expiry_year" binding:"required"`
		Name              string   `json:"name,omitempty"`
		CVV               string   `json:"cvv,omitempty"`
		BillingAddress    *Address `json:"billing_address,omitempty"`
		Phone             *Phone   `json:"phone,omitempty"`
		InvoiceNumber     string   `json:"invoice_number,omitempty"`
		PaymentCountry    string   `json:"payment_country,omitempty"`
		AccountHolderName string   `json:"account_holder_name,omitempty"`
		BillingDescriptor string   `json:"billing_descriptor,omitempty"`
	}
	// WalletToken ...
	WalletToken struct {
		Type      string       `json:"type" binding:"required"`
		TokenData *PaymentData `json:"token_data,omitempty"`
	}
	// ThreeDS - Information required for 3D Secure payments
	ThreeDS struct {
		Enabled    *bool   `json:"enabled,omitempty"`
		AttemptN3d *bool   `json:"attempt_n3d,omitempty"`
		ECI        *string `json:"eci,omitempty"`
		Cryptogram *string `json:"cryptogram,omitempty"`
		XID        *string `json:"xid,omitempty"`
		Version    *string `json:"version,omitempty"`
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
	// Billing - The billing details.
	Billing struct {
		Address Address `json:"address,omitempty"`
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
		Aft                      bool    `json:"aft,omitempty"`
		DLocal                   *DLocal `json:"dlocal,omitempty"`
		AcquirerTransactionID    *string `json:"acquirer_transaction_id,omitempty"`
		RetrievalReferenceNumber *string `json:"retrieval_reference_number,omitempty"`
	}

	// DLocalAPM ...
	DLocalAPM struct {
		Type            string    `json:"type" binding:"required"`
		IntegrationType string    `json:"integration_type,omitempty" binding:"required"`
		Country         string    `json:"country" binding:"required"`
		Description     string    `json:"description,omitempty"`
		Payer           *Customer `json:"payer,omitempty"`
	}

	// Fawry ...
	Fawry struct {
		Type           string          `json:"type" binding:"required"`
		Description    string          `json:"description,omitempty"`
		CustomerMobile string          `json:"customer_mobile,omitempty"`
		CustomerEmail  string          `json:"customer_email,omitempty"`
		Products       *[]FawryProduct `json:"products,omitempty"`
	}

	// FawryProduct ...
	FawryProduct struct {
		ProductID   string `json:"product_id,omitempty"`
		Quantity    int    `json:"quantity,omitempty"`
		Price       int    `json:"price,omitempty"`
		Description string `json:"description,omitempty"`
	}

	// GiroPay ...
	GiroPay struct {
		Type       string      `json:"type" binding:"required"`
		Purpose    string      `json:"purpose,omitempty" binding:"required"`
		BIC        string      `json:"bic" binding:"required"`
		InfoFields []InfoField `json:"info_fields,omitempty"`
	}

	// EPS ...
	EPS struct {
		Type    string `json:"type" binding:"required"`
		Purpose string `json:"purpose,omitempty" binding:"required"`
	}

	// InfoField ...
	InfoField struct {
		Label string `json:"label,omitempty"`
		Text  string `json:"text,omitempty"`
	}

	// IDeal ...
	IDeal struct {
		Type        string `json:"type" binding:"required"`
		BIC         string `json:"bic,omitempty" binding:"required"`
		Description string `json:"description,omitempty"`
		Language    string `json:"language,omitempty"`
	}

	// DLocal - Processing information required for dLocal payments.
	DLocal struct {
		Country     string       `json:"country,omitempty"`
		Payer       *Customer    `json:"payer,omitempty"`
		Installment *Installment `json:"installment,omitempty"`
	}

	// CreditSessions - Klarna's Credit Sessions
	CreditSessions struct {
		PurchaseCountry string        `json:"purchase_country,omitempty"`
		Currency        string        `json:"currency,omitempty"`
		Locale          string        `json:"locale,omitempty"`
		Amount          *int          `json:"amount,omitempty"`
		TaxAmount       *int          `json:"tax_amount,omitempty"`
		Products        *[]OrderLines `json:"products,omitempty"`
	}
	// OrderLines - Klarna's OrderLines
	OrderLines struct {
		Name           string `json:"name,omitempty"`
		Quantity       *int   `json:"quantity,omitempty"`
		UnitPrice      *int   `json:"unit_price,omitempty"`
		TaxRate        *int   `json:"tax_rate,omitempty"`
		TotalAmount    *int   `json:"total_amount,omitempty"`
		TotalTaxAmount *int   `json:"total_tax_amount,omitempty"`
	}
	// CreditSessionsResponse - Klarna's Credit Sessions Response
	CreditSessionsResponse struct {
		SessionID               string                     `json:"session_id,omitempty"`
		ClientToken             string                     `json:"client_token,omitempty"`
		PaymentMethodCategories *[]PaymentMethodCategories `json:"payment_method_categories,omitempty"`
		Links                   *Links                     `json:"_links,omitempty"`
	}

	// Klarna ...
	Klarna struct {
		Type               string                 `json:"type" binding:"required"`
		AuthorizationToken string                 `json:"authorization_token,omitempty"`
		Locale             string                 `json:"locale,omitempty"`
		PurchaseCountry    string                 `json:"purchase_country,omitempty"`
		TaxAmount          *int                   `json:"tax_amount,omitempty"`
		MerchantReference1 string                 `json:"merchant_reference1,omitempty"`
		MerchantReference2 string                 `json:"merchant_reference2,omitempty"`
		BillingAddress     *KlarnaBillingAddress  `json:"billing_address,omitempty"`
		ShippingAddress    *KlarnaShippingAddress `json:"shipping_address,omitempty"`
		Customer           *KlarnaCustomer        `json:"customer,omitempty"`
		Products           *[]OrderLines          `json:"products,omitempty"`
	}

	// KlarnaBillingAddress ...
	KlarnaBillingAddress struct {
		GivenName      string `json:"given_name" binding:"required"`
		FamilyName     string `json:"family_name" binding:"required"`
		Email          string `json:"email" binding:"required"`
		Title          string `json:"title" binding:"required"`
		StreetAddress  string `json:"street_address" binding:"required"`
		StreetAddress2 string `json:"street_address2" binding:"required"`
		PostalCode     string `json:"postal_code" binding:"required"`
		City           string `json:"city" binding:"required"`
		Phone          string `json:"phone" binding:"required"`
		Country        string `json:"country" binding:"required"`
	}
	// KlarnaShippingAddress ...
	KlarnaShippingAddress struct {
		GivenName      string `json:"given_name" binding:"required"`
		FamilyName     string `json:"family_name" binding:"required"`
		Email          string `json:"email" binding:"required"`
		Title          string `json:"title" binding:"required"`
		StreetAddress  string `json:"street_address" binding:"required"`
		StreetAddress2 string `json:"street_address2" binding:"required"`
		PostalCode     string `json:"postal_code" binding:"required"`
		City           string `json:"city" binding:"required"`
		Phone          string `json:"phone" binding:"required"`
		Country        string `json:"country" binding:"required"`
	}

	// KlarnaCustomer ...
	KlarnaCustomer struct {
		DateOfBirth string `json:"date_of_birth" binding:"required"`
		Gender      string `json:"gender" binding:"required"`
	}

	// PaymentMethodCategories - Klarna's PaymentMethodCategories
	PaymentMethodCategories struct {
		AssetURLS  *AssetURLS `json:"asset_urls,omitempty"`
		Identifier string     `json:"identifier,omitempty"`
		Name       string     `json:"name,omitempty"`
	}

	// AssetURLS -
	AssetURLS struct {
		Descriptive string `json:"identifier,omitempty"`
		Standard    string `json:"standard,omitempty"`
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

type (

	// Disputes ...
	Disputes struct {
		Limit      *int       `json:"limit,omitempty"`
		Skip       *int       `json:"skip,omitempty"`
		From       *string    `json:"from,omitempty"`
		To         *string    `json:"to,omitempty"`
		TotalCount *int       `json:"total_count,omitempty"`
		Data       *[]Dispute `json:"data,omitempty"`
	}

	// Dispute ...
	Dispute struct {
		ID                 string      `json:"id,omitempty"`
		Category           string      `json:"category,omitempty"`
		Status             string      `json:"status,omitempty"`
		Amount             int         `json:"amount,omitempty"`
		Currency           string      `json:"currency,omitempty"`
		PaymentID          string      `json:"payment_id,omitempty"`
		PaymentReference   string      `json:"payment_reference,omitempty"`
		PaymentMethod      string      `json:"payment_method,omitempty"`
		PaymentArn         string      `json:"payment_arn,omitempty"`
		ReceivedOn         string      `json:"received_on,omitempty"`
		LastUpdate         string      `json:"last_update,omitempty"`
		EvidenceRequiredBy string      `json:"evidence_required_by,omitempty"`
		Links              *EventLinks `json:"_links,omitempty"`
		RelevantEvidence   *[]string   `json:"relevant_evidence,omitempty"`
		Payment            *Resp       `json:"payment,omitempty"`
	}
	// File ...
	File struct {
		ID    string      `json:"id,omitempty"`
		Links *EventLinks `json:"_links,omitempty"`
	}
)

const (
	// Pending ...
	Pending string = "Pending"
	// Authorized ...
	Authorized string = "Authorized"
	// Declined ...
	Declined string = "Declined"
	// Captured ...
	Captured string = "Captured"
	// CardVerified ...
	CardVerified string = "Card Verified"
)

const (
	// Webhooks ...
	Webhooks string = "webhooks"
	// Payments ...
	Payments string = "payments"
	// PaymentActions ...
	PaymentActions string = "Payment_Actions"
)

func init() {

	httpclient = resty.New()
	httpclient.SetDebug(true)
	httpclient.SetTimeout(requestTimeout)
}

func main() {

	// opt := option.WithCredentialsFile(firebaseAccountKey)
	// conf := &firebase.Config{
	// 	DatabaseURL: "https://cko-go-demo.firebaseio.com/",
	// }
	// app, err := firebase.NewApp(ctx, conf, opt)
	// if err != nil {
	// 	log.Fatalf("firebase.NewApp: %v", err)
	// }
	// // access real-time database from firebase default app
	// firebaseDBClient, err = app.Database(ctx)
	// if err != nil {
	// 	log.Fatalf("app.Firestore: %v", err)
	// }
	// paymentRef = firebaseDBClient.NewRef(Payments)
	// webhooksRef = firebaseDBClient.NewRef(Webhooks)

	r := gin.Default()
	r.StaticFile("/", "./static/key.html")
	r.StaticFile("/introduction", "./static/documents.html")
	r.StaticFile("/500", "./static/500-error.html")
	r.StaticFile("/checkout", "./static/checkout-page.html")
	r.StaticFile("/cart", "./static/cart.html")
	r.StaticFile("/shop", "./static/shop.html")
	r.StaticFile("/404", "./static/404-error.html")
	r.StaticFile("/invoice", "./static/invoice-page.html")
	r.StaticFile("/product", "./static/product-page.html")
	r.StaticFile("/reset", "./static/reset-page.html")
	r.StaticFile("/manage", "./static/manage.html")
	r.StaticFile("/manage/webhooks", "./static/manage-webhooks.html")
	r.StaticFile("/manage/disputes", "./static/manage-disputes.html")

	r.Static("/.well-known", "./static/.well-known")
	r.Static("/images", "./static/images")
	r.Static("/assets", "./static/assets")
	r.Static("/public", "./static")
	r.POST("/getApplePaySession", getApplePaySession)
	r.POST("/processApplePayResponse", processApplePayResponse)
	r.POST("/processGooglePayResponse", processGooglePayResponse)
	r.POST("/webhooks", processWebhooks)
	r.GET("/webhooks", getWebhooks)
	r.GET("/actions", getActions)
	r.GET("/payments", paymentsDetail)
	r.POST("/voids", voidsPayment)
	r.POST("/captures", capturesPayment)
	r.POST("/refunds", refundsPayment)
	r.POST("/klarna/klarna-order", placeKlarnaOrder)
	r.GET("/events/:id/*action", getEventNotifications)
	r.POST("/", requestCardPayment)
	r.GET("/paypal", requestPayPalPayment)
	r.GET("/giropay", requestGiropayPayment)
	r.GET("/eps", requestEPSPayment)
	r.GET("/alipay", requestAlipayPayment)
	r.GET("/wechatpay", requestWeChatpayPayment)
	r.GET("/enet", requestENetPayment)
	r.GET("/poli", requestPoliPayment)
	r.GET("/sofort", requestSofortPayment)
	r.GET("/bancontact", requestBancontactPayment)
	r.GET("/ideal", requestIDealPayment)
	r.GET("/boleto", requestBoletoPayment)
	r.GET("/baloto", requestBalotoPayment)
	r.GET("/oxxo", requestOxxoPayment)
	r.GET("/pagofacil", requestPagofacilPayment)
	r.GET("/rapipago", requestRapipagoPayment)
	r.GET("/fawry", requestFawryPayment)
	r.GET("/klarna/credit-sessions", requestKlarnaCreditSessions)
	r.GET("/success", successCardPayment)
	r.GET("/error", errorCardPayment)
	r.GET("/hosted-payment-page", requestHostedPaymentPage)
	r.GET("/manage/subscribedWebhooks", getSubscribedWebhooks)
	r.GET("/manage/getdisputes", getDisputes)
	r.GET("/manage/getdispute", getDispute)
	r.POST("/manage/files", uploadFile)
	r.PUT("/manage/disputes/:id/*action", provideEvidence)
	r.POST("/manage/disputes/:id/*action", postDisputeEvidence)
	r.GET("/manage/webhookEventTypes", getWebhookEventTypes)
	r.GET("/manage/webhooks/:id", getWebhook)
	r.POST("/manage/webhooks", registerWebhook)
	r.PUT("/manage/webhooks/:id", updateWebhook)
	r.POST("/manage/activate/webhook/:id/*action", updateWebhookEvent)
	r.DELETE("/manage/activate/webhook/:id", removeWebhookEvent)

	r.LoadHTMLGlob("./static/templates/*")

	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}
	r.Run(":" + port)
}

func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

func removeCardAfterToken(c *gin.Context) {

	// remove CC raw from DB
	// remove CC raw from cache
}

func requestCardPayment(c *gin.Context) {

	token := c.PostForm(cardToken)
	removeCardAfterToken(c)

	var amount = c.PostForm("amount")

	if len(token) < 1 || len(amount) < 1 {
		var keyPath = localFirebaseAccountKey
		if strings.Contains(c.Request.Host, "evening-reef-89950") {
			databaseURL = "https://cko-go-demo.firebaseio.com/"
			keyPath = firebaseAccountKey
		}
		opt := option.WithCredentialsFile(keyPath)
		conf := &firebase.Config{
			DatabaseURL: databaseURL,
		}
		app, err := firebase.NewApp(ctx, conf, opt)
		if err != nil {
			log.Fatalf("firebase.NewApp: %v", err)
		}
		// access real-time database from firebase default app
		firebaseDBClient, err = app.Database(ctx)
		if err != nil {
			log.Fatalf("app.Firestore: %v", err)
		}
		paymentRef = firebaseDBClient.NewRef(Payments)
		webhooksRef = firebaseDBClient.NewRef(Webhooks)

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
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = reference + " - " + randString

	var currency = c.PostForm("currency")
	threeds, _ := strconv.ParseBool(c.PostForm("three-ds"))
	attemptN3d, _ := strconv.ParseBool(c.PostForm("attempt-n3d"))
	autoCapture, _ := strconv.ParseBool(c.PostForm("auto-capture"))
	captureDelay, _ := strconv.ParseBool(c.PostForm("capture-delay"))

	var source = CardToken{Type: tokenType, Token: token}
	var threeDS = &ThreeDS{Enabled: &threeds, AttemptN3d: &attemptN3d}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randString, UDF2: "USER-123(Internal ID)"}
	var total int = 0
	description = randReference

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 1
	}

	var captureOn time.Time
	var captureOnRFC3339 string

	if captureDelay {
		captureOn = time.Now().Add(time.Minute * 1)
		captureOnRFC3339 = captureOn.Format(time.RFC3339)
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
		Capture:           &autoCapture,
		CaptureOn:         &captureOnRFC3339,
	}

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		// SetHeader("Accept", "application/json; charset=utf-16"). Dont use UTF-16
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetBody(body).
		SetResult(Resp{}).
		SetError(Error{}).
		Post(baseURL + paymentPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	// Save Webhook in Firebase
	currentPayment = resp.Result().(*Resp)
	tempRef := resp.Result().(*Resp).Reference
	tempStatus := resp.Result().(*Resp).Status
	if err := paymentRef.Child(tempRef+"/status/"+tempStatus).Set(ctx, resp.Result()); err != nil {
		log.Fatalln("Error setting value:", err)
	}
	showHTMLPage(resp.Result().(*Resp), c)
}

func successCardPayment(c *gin.Context) {

	path := c.FullPath()
	if !strings.Contains(path, "/success") {
		c.Status(http.StatusBadRequest)
		return
	}
	sessionID, exist := c.GetQuery(sessionIDKey)
	if !exist {
		paymentID, exist := c.GetQuery(paymentIDKey)
		if !exist {
			c.Status(http.StatusBadRequest)
			return
		}
		if len(paymentID) < 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(Resp{}).
			SetError(Error{}).
			Get(baseURL + paymentPath + "/" + paymentID)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		if resp.Body() == nil {
			c.Status(http.StatusBadRequest)
			return
		}
		// Save Webhook in Firebase
		currentPayment = resp.Result().(*Resp)
		tempRef := resp.Result().(*Resp).Reference
		tempStatus := resp.Result().(*Resp).Status
		if err := paymentRef.Child(tempRef+"/status/"+tempStatus).Set(ctx, resp.Result()); err != nil {
			log.Fatalln("Error setting value:9", err)
		}
		var res = resp.Result().(*Resp)
		res.JSON = string(resp.Body())
		showHTMLPage(res, c)
		return
	}
	if len(sessionID) < 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Resp{}).
		SetError(Error{}).
		Get(baseURL + paymentPath + "/" + sessionID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if resp.Body() == nil {
		c.Status(http.StatusBadRequest)
		return
	}
	// Save Webhook in Firebase
	currentPayment = resp.Result().(*Resp)
	tempRef := resp.Result().(*Resp).Reference
	tempStatus := resp.Result().(*Resp).Status
	if err := paymentRef.Child(tempRef+"/status/"+tempStatus).Set(ctx, resp.Result()); err != nil {
		log.Fatalln("Error setting value:9", err)
	}
	var res = resp.Result().(*Resp)
	res.JSON = string(resp.Body())
	showHTMLPage(res, c)
}

func errorCardPayment(c *gin.Context) {
	path := c.FullPath()
	if path != "/error" {
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
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Resp{}).
		SetError(Error{}).
		Get(baseURL + paymentPath + "/" + sessionID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if resp.Body() == nil {
		c.Status(http.StatusBadRequest)
		return
	}
	// Save Webhook in Firebase
	currentPayment = resp.Result().(*Resp)
	tempRef := resp.Result().(*Resp).Reference
	tempStatus := resp.Result().(*Resp).Status
	if err := paymentRef.Child(tempRef+"/status/"+tempStatus).Set(ctx, resp.Result()); err != nil {
		log.Fatalln("Error setting value:9", err)
	}
	var res = resp.Result().(*Resp)
	res.JSON = string(resp.Body())
	showHTMLPage(res, c)
}

func requestPayPalPayment(c *gin.Context) {

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}

	var source = CardToken{Type: "paypal", InvoiceNumber: "PAYPAL - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
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

	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "20"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	var source = CardToken{Type: "alipay"}
	var body = Payment{
		Source:      source,
		Amount:      total,
		Currency:    "USD",
		PaymentType: paymentType,
		Reference:   reference,
		Description: description,
		SuccessURL:  successURL,
		FailureURL:  failureURL,
	}

	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}

	var source = CardToken{Type: "wechatpay", InvoiceNumber: "WECHATPAY - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
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

	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}

	var source = CardToken{Type: "enets", InvoiceNumber: "eNETS - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
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

	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}

	var source = CardToken{Type: "poli", InvoiceNumber: "POLI - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
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

	resp, err := httpclient.R().
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

func requestGiropayPayment(c *gin.Context) {
	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 1
	}

	var source = GiroPay{Type: "giropay", Purpose: "GiroPay - A12345", BIC: "TESTDETT421"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "EUR",
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

	resp, err := httpclient.R().
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

func requestEPSPayment(c *gin.Context) {
	var total int = 0
	var amount = "100"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 1
	}

	var source = EPS{Type: "eps", Purpose: "EPS - A12345"}
	var body = Payment{
		Source:     source,
		Amount:     total,
		Currency:   "EUR",
		Reference:  reference,
		SuccessURL: successURL,
		FailureURL: failureURL,
	}

	resp, err := httpclient.R().
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

func requestSofortPayment(c *gin.Context) {

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 1
	}

	var source = CardToken{Type: "sofort", InvoiceNumber: "Sofort - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "EUR",
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

	resp, err := httpclient.R().
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

func requestBancontactPayment(c *gin.Context) {

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	var source = CardToken{Type: "bancontact", PaymentCountry: "BE", AccountHolderName: "SHIUH YAW", BillingDescriptor: "Bancontact - A12345"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: "A123456", UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "EUR",
		PaymentType:       paymentType,
		Reference:         "Ord Bancontact - A12345",
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
	}

	resp, err := httpclient.R().
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

func requestIDealPayment(c *gin.Context) {
	var total int = 0
	var amount = "1"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	capture := true
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "" + " - " + randString
	// GET bic: INGBNL2A from https://api.sandbox.checkout.com/ideal-external/issuers
	// Use 100 for success
	// Use 200 for Void/Cancel
	// Use 300 for expired
	// Use 400 for Pending
	// Use 500 for Fail
	// Use 700 for SO1000 Failure in system
	var source = IDeal{Type: "ideal", BIC: "INGBNL2A", Description: "ideal", Language: "it"}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "EUR",
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
		Capture:           &capture,
	}

	resp, err := httpclient.R().
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

func requestBoletoPayment(c *gin.Context) {
	var total int = 0
	var amount = "1"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Boleto" + " - " + randString

	var source = DLocalAPM{Type: "boleto", IntegrationType: "redirect", Country: "BR", Description: "Boleto Payment", Payer: &Customer{
		Name:     "Yaw",
		Email:    email,
		Document: "53033315550",
	}}
	var body = Payment{
		Source:      source,
		Amount:      total,
		Currency:    "USD",
		PaymentType: paymentType,
		Reference:   randReference,
		SuccessURL:  successURL,
		FailureURL:  failureURL,
	}

	resp, err := httpclient.R().
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

func requestBalotoPayment(c *gin.Context) {
	var total int = 0
	var amount = "5001"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Baloto" + " - " + randString

	var source = DLocalAPM{Type: "baloto", IntegrationType: "redirect", Country: "CO", Description: "Baloto", Payer: &Customer{
		Name:     name,
		Email:    email,
		Document: "53033315550",
	}}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "COP",
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
	}

	resp, err := httpclient.R().
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

func requestOxxoPayment(c *gin.Context) {
	var total int = 0
	var amount = "5001"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "OXXO" + " - " + randString

	var source = DLocalAPM{Type: "oxxo", IntegrationType: "redirect", Country: "MX", Description: "OXXO", Payer: &Customer{
		Name:     name,
		Email:    email,
		Document: "53033315550",
	}}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          "MXN",
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
	}

	resp, err := httpclient.R().
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

func requestHostedPaymentPage(c *gin.Context) {

	var total int = 0
	var amount = "20"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Hosted Payment Page" + " - " + randString

	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Billing: &Billing{
			Address{
				Country: "SG",
			},
		},
		Risk:       risk,
		SuccessURL: successURL,
		FailureURL: failureURL,
		CancelURL:  failureURL,
		Metadata:   metadata,
		Amount:     total,
		Currency:   "SGD",
	}

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetBody(body).
		SetResult(Resp{}).
		SetError(Error{}).
		Post(baseURL + hostedPaymentsPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	showHTMLPage(resp.Result().(*Resp), c)
}

func requestPagofacilPayment(c *gin.Context) {
	var total int = 0
	var amount = "5001"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Pagofacil" + " - " + randString

	var source = DLocalAPM{Type: "pagofacil", IntegrationType: "redirect", Country: "AR", Description: "Pagofacil", Payer: &Customer{
		Name:     "Yaw",
		Email:    email,
		Document: "53033315550",
	}}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
		Amount:            total,
		Currency:          "ARS",
	}

	resp, err := httpclient.R().
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

func requestRapipagoPayment(c *gin.Context) {
	var total int = 0
	var amount = "5001"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Rapipago" + " - " + randString

	var source = DLocalAPM{Type: "rapipago", IntegrationType: "redirect", Country: "AR", Description: "Rapipago", Payer: &Customer{
		Name:     "Yaw",
		Email:    email,
		Document: "53033315550",
	}}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
		Amount:            total,
		Currency:          "ARS",
	}

	resp, err := httpclient.R().
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

func requestFawryPayment(c *gin.Context) {
	var total int = 0
	var amount = "1000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = "Fawry" + " - " + randString
	var products = []FawryProduct{
		{
			ProductID:   randReference,
			Quantity:    1,
			Price:       total,
			Description: randReference,
		},
	}

	var source = Fawry{Type: "fawry", Description: "Fawry Demo Payment", CustomerEmail: email, CustomerMobile: "01058375055", Products: &products}

	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var risk = &Risk{Enabled: true}
	var metadata = &Metadata{UDF1: randReference, UDF2: "USER-123(Internal ID)"}
	var body = Payment{
		Source:            source,
		PaymentType:       paymentType,
		Reference:         randReference,
		Description:       description,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		Risk:              risk,
		SuccessURL:        successURL,
		FailureURL:        failureURL,
		Metadata:          metadata,
		Amount:            total,
		Currency:          "EGP",
	}

	resp, err := httpclient.R().
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

func requestKlarnaCreditSessions(c *gin.Context) {

	var total int = 0
	var amount = "1000"
	convertedAmount, err := strconv.Atoi(amount)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	total = convertedAmount
	var one = 1
	var zero = 0
	var products = []OrderLines{
		{
			Name:           "Brown leather belt",
			Quantity:       &one,
			UnitPrice:      &total,
			TaxRate:        &zero,
			TotalAmount:    &total,
			TotalTaxAmount: &zero,
		},
	}

	var creditSessions = CreditSessions{
		PurchaseCountry: "GB",
		Currency:        "GBP",
		Locale:          "en-GB",
		Amount:          &total,
		TaxAmount:       &zero,
		Products:        &products,
	}
	resp, err := httpclient.R().
		SetHeader(authKey, publicKey).
		SetBody(creditSessions).
		SetResult(CreditSessionsResponse{}).
		SetError(Error{}).
		Post(baseURL + "klarna-external/credit-sessions")
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	var sessions = resp.Result().(*CreditSessionsResponse)
	showKlarnaWidget(sessions, c)
}

func placeKlarnaOrder(c *gin.Context) {

	authorization_token, exist := c.GetQuery("authorization_token")
	if !exist {
		c.HTML(http.StatusOK, errorHTML, "")
	} else {
		var total int = 0
		var amount = "1000"
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount
		var one = 1
		var zero = 0
		var products = []OrderLines{
			{
				Name:           "Brown leather belt",
				Quantity:       &one,
				UnitPrice:      &total,
				TaxRate:        &zero,
				TotalAmount:    &total,
				TotalTaxAmount: &zero,
			},
		}
		var source = Klarna{
			Type:               "klarna",
			AuthorizationToken: authorization_token,
			Locale:             "en-GB",
			PurchaseCountry:    "GB",
			TaxAmount:          &zero,
			BillingAddress: &KlarnaBillingAddress{
				GivenName:      "John",
				FamilyName:     "Doe",
				Email:          "johndoe@email.com",
				Title:          "Mr",
				StreetAddress:  "13 New Burlington St",
				StreetAddress2: "Apt 214",
				PostalCode:     "W13 3BG",
				City:           "London",
				Phone:          "01895808221",
				Country:        "GB",
			},
			ShippingAddress: &KlarnaShippingAddress{
				GivenName:      "John",
				FamilyName:     "Doe",
				Email:          "johndoe@email.com",
				Title:          "Mr",
				StreetAddress:  "13 New Burlington St",
				StreetAddress2: "Apt 214",
				PostalCode:     "W13 3BG",
				City:           "London",
				Phone:          "01895808221",
				Country:        "GB",
			},
			Customer: &KlarnaCustomer{
				DateOfBirth: "1970-01-01",
				Gender:      "male",
			},
			MerchantReference1: "klarna's merchant reference 1",
			MerchantReference2: "klarna's merchant reference 2",
			Products:           &products,
		}

		capture := false
		var body = Payment{
			Source:    source,
			Amount:    total,
			Currency:  "GBP",
			Capture:   &capture,
			Reference: "Klarna Order Reference",
		}

		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetBody(body).
			SetResult(Resp{}).
			SetError(Error{}).
			Post(baseURL + paymentPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		showKlarnaHTMLPage(resp.Result().(*Resp), c)
	}
}

func getApplePaySession(c *gin.Context) {
	r := &struct{ URL string }{}
	if err := c.BindJSON(r); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if err := checkSessionURL(r.URL); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	cert, err := tls.LoadX509KeyPair(certPem, certKey)
	if err != nil {
		log.Fatalf("ERROR httpclient certificate: %s", err)
	}
	httpclient.SetCertificates(cert)
	payload, err := httpclient.R().
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
		c.Status(http.StatusBadRequest)
		return
	}
	var body = WalletToken{
		Type:      applePayType,
		TokenData: r.Token.PaymentData,
	}
	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "2000"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount
	}
	var source = CardToken{
		Type:  tokenType,
		Token: t.Token,
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = reference + " - " + randString
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	threeds := true
	attemptN3d := false
	var threeDS = &ThreeDS{Enabled: &threeds, AttemptN3d: &attemptN3d}

	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          currency,
		Reference:         "ApplePay " + randReference,
		Customer:          customer,
		BillingDescriptor: billingDescriptor,
		ThreeDS:           threeDS,
	}
	resp, err := httpclient.R().
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

// checkSessionURL validates the request URL sent by the httpclient to check that it
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
		c.Status(http.StatusBadRequest)
		return
	}
	var body = WalletToken{
		Type:      googlePayType,
		TokenData: r,
	}
	log.Println(body)
	resp, err := httpclient.R().
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

	var total int = 0
	var amount = "2"

	if strings.Contains(amount, ".") {
		convertedAmount, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var floatAmount = convertedAmount * 100
		total = int(floatAmount)
	} else {
		convertedAmount, err := strconv.Atoi(amount)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		total = convertedAmount * 100
	}
	var source = CardToken{
		Type:  tokenType,
		Token: t.Token,
	}
	rand.Seed(time.Now().UnixNano())
	randomNum := random(1000, 10000000000)
	var randInteger = rand.Intn(randomNum)
	var randString = strconv.Itoa(randInteger)
	var randReference = reference + " - " + randString
	threeds := true
	attemptN3d := true
	var threeDS = &ThreeDS{Enabled: &threeds, AttemptN3d: &attemptN3d}
	var customer = &Customer{Email: email, Name: name}
	var billingDescriptor = &BillingDescriptor{Name: "25 Characters", City: "13 Characters"}
	var body = Payment{
		Source:            source,
		Amount:            total,
		Currency:          currency,
		Reference:         "GooglePay " + randReference,
		Customer:          customer,
		ThreeDS:           threeDS,
		BillingDescriptor: billingDescriptor,
	}
	resp, err := httpclient.R().
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

func showKlarnaWidget(resp *CreditSessionsResponse, c *gin.Context) {

	fmt.Println(resp)
	c.HTML(http.StatusOK, klarnaHTML, resp)
}

func showKlarnaHTMLPage(resp *Resp, c *gin.Context) {

	fmt.Println(resp.Status)
	fmt.Println(resp.Links.RedirectURL.URLString)
	switch resp.Status {
	case "Authorized":
		c.Redirect(http.StatusMovedPermanently, resp.Links.RedirectURL.URLString)
		c.Abort()
		return
	default:
		c.HTML(http.StatusOK, successHTML, resp)
		return
	}
}

func showHTMLPage(resp *Resp, c *gin.Context) {

	fmt.Println(resp)
	switch resp.Status {
	case "":
		c.Redirect(http.StatusMovedPermanently, resp.Links.RedirectURL.URLString)
		c.Abort()
		return
	case Pending:
		c.Redirect(http.StatusMovedPermanently, resp.Links.RedirectURL.URLString)
		c.Abort()
		return
	case Captured:
		c.HTML(http.StatusOK, successHTML, resp)
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

type (

	// Webhook ...
	Webhook struct {
		ID          *string        `json:"id,omitempty"`
		URL         *string        `json:"url,omitempty"`
		Active      *bool          `json:"active,omitempty"`
		Headers     *WebhookHeader `json:"headers,omitempty"`
		ContentType string         `json:"content_type,omitempty"`
		EventTypes  *[]string      `json:"event_types,omitempty"`
		Links       *EventLinks    `json:"_links,omitempty"`
		Version     *string        `json:"version,omitempty"`
	}
	// WebhookType ...
	WebhookType struct {
		EventTypes *[]string `json:"event_types,omitempty"`
		Version    *string   `json:"version,omitempty"`
	}

	// WebhookHeader ...
	WebhookHeader struct {
		Authorization *string `json:"Authorization,omitempty"`
	}

	// Event ...
	Event struct {
		ID            *string        `json:"id,omitempty"`
		Type          *string        `json:"type" binding:"required"`
		Version       *string        `json:"version,omitempty"`
		CreateOn      *string        `json:"created_on,omitempty"`
		Data          *EventData     `json:"data,omitempty"`
		Notifications []Notification `json:"notifications,omitempty"`
		Links         *EventLinks    `json:"_links,omitempty"`
	}
	// EventData ...
	EventData struct {
		ActionID        *string     `json:"action_id,omitempty"`
		PaymentType     *string     `json:"payment_type,omitempty"`
		AuthCode        *string     `json:"auth_code,omitempty"`
		ResponseCode    *string     `json:"response_code,omitempty"`
		ResponseSummary *string     `json:"response_summary,omitempty"`
		SchemeID        *string     `json:"scheme_id,omitempty"`
		ThreeDS         *ThreeDS    `json:"3ds,omitempty"`
		Source          *Source     `json:"source,omitempty"`
		Customer        *Customer   `json:"customer,omitempty"`
		Processing      *Processing `json:"processing,omitempty"`
		Amount          *int        `json:"amount,omitempty"`
		Metadata        *Metadata   `json:"metadata,omitempty"`
		Risk            *Risk       `json:"risk,omitempty"`
		Currency        *string     `json:"currency,omitempty"`
		ProcessedOn     *string     `json:"processed_on,omitempty"`
		Reference       *string     `json:"reference,omitempty"`
		ID              *string     `json:"id,omitempty"`
	}
	// EventLinks ...
	EventLinks struct {
		Self          *EventLink `json:"self,omitempty"`
		Payment       *EventLink `json:"payment,omitempty"`
		WebhooksRetry *EventLink `json:"webhooks-retry,omitempty"`
		WebhookRetry  *EventLink `json:"webhook-retry,omitempty"`
		Evidence      *EventLink `json:"evidence,omitempty"`
	}
	// EventLink ...
	EventLink struct {
		Href *string `json:"href,omitempty"`
	}
	// Notification ...
	Notification struct {
		URL              *string     `json:"url,omitempty"`
		ID               *string     `json:"id,omitempty"`
		ContentType      *string     `json:"content_type,omitempty"`
		NotificationType *string     `json:"notification_type,omitempty"`
		Success          *bool       `json:"success,omitempty"`
		Links            *EventLinks `json:"_links,omitempty"`
		Attempts         *[]Attempts `json:"attempts,omitempty"`
	}
	// Attempts ...
	Attempts struct {
		StatusCode *int    `json:"status_code,omitempty"`
		SendMode   *string `json:"send_mode,omitempty"`
		Timestamp  *string `json:"timestamp,omitempty"`
	}
)

func processWebhooks(c *gin.Context) {

	event := &Event{}
	if err := c.BindJSON(event); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	// Save Webhook in Firebase
	if err := webhooksRef.Child(*event.Data.Reference+"/event/"+*event.Type).Set(ctx, &event); err != nil {
		log.Fatalln("Error setting value:", err)
	}
}

func getWebhooks(c *gin.Context) {

	refID, exist := c.GetQuery(referenceID)
	if !exist {
		c.Status(http.StatusBadRequest)
		return
	}
	if len(refID) < 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	events := []Event{}
	paymentWebhookRef := firebaseDBClient.NewRef(Webhooks + "/" + refID + "/event")
	results, err := paymentWebhookRef.OrderByChild("created_on").GetOrdered(ctx)
	if err != nil {
		log.Fatalln("Error querying database:", err)
	}
	for _, r := range results {
		var event Event
		if err := r.Unmarshal(&event); err != nil {
			log.Fatalln("Error Unmarshal result:", err)
		}
		events = append(events, event)
	}
	c.JSON(200, events)
}

func getActions(c *gin.Context) {

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult([]Action{}).
		SetError(Error{}).
		Get(baseURL + paymentPath + "/" + currentPayment.ID + "/" + actionPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if resp.Body() == nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func voidsPayment(c *gin.Context) {
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Action{}).
		SetError(Error{}).
		Post(baseURL + paymentPath + "/" + currentPayment.ID + "/" + voidPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	if resp.Body() == nil {
		c.Status(http.StatusBadRequest)
		return
	}
	getPaymentsDetail(currentPayment.ID, c)
}

func capturesPayment(c *gin.Context) {

	captureAmount, exist := c.GetQuery("amount")
	if !exist {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(Action{}).
			SetError(Error{}).
			Post(baseURL + paymentPath + "/" + currentPayment.ID + "/" + capturesPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		if resp.Body() == nil {
			c.Status(http.StatusBadRequest)
			return
		}
		getPaymentsDetail(currentPayment.ID, c)

	} else {
		if len(captureAmount) < 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		var total int = 0
		if strings.Contains(captureAmount, ".") {
			convertedAmount, err := strconv.ParseFloat(captureAmount, 64)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			var floatAmount = convertedAmount * 100
			total = int(floatAmount)
		} else {
			convertedAmount, err := strconv.Atoi(captureAmount)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			total = convertedAmount * 100
		}
		body := make(map[string]int)
		body["amount"] = total
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetBody(body).
			SetResult(Action{}).
			SetError(Error{}).
			Post(baseURL + paymentPath + "/" + currentPayment.ID + "/" + capturesPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		if resp.Body() == nil {
			c.Status(http.StatusBadRequest)
			return
		}
		getPaymentsDetail(currentPayment.ID, c)
	}
}

func refundsPayment(c *gin.Context) {

	refundAmount, exist := c.GetQuery("amount")
	if !exist {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(Action{}).
			SetError(Error{}).
			Post(baseURL + paymentPath + "/" + currentPayment.ID + "/" + refundPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		if resp.Body() == nil {
			c.Status(http.StatusBadRequest)
			return
		}
		// Save Webhook in Firebase
		getPaymentsDetail(currentPayment.ID, c)
	} else {
		if len(refundAmount) < 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		var total int = 0
		if strings.Contains(refundAmount, ".") {
			convertedAmount, err := strconv.ParseFloat(refundAmount, 64)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			var floatAmount = convertedAmount * 100
			total = int(floatAmount)
		} else {
			convertedAmount, err := strconv.Atoi(refundAmount)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			total = convertedAmount * 100
		}
		body := make(map[string]int)
		body["amount"] = total

		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetBody(body).
			SetResult(Action{}).
			SetError(Error{}).
			Post(baseURL + paymentPath + "/" + currentPayment.ID + "/" + refundPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		if resp.Body() == nil {
			c.Status(http.StatusBadRequest)
			return
		}
		// Save Webhook in Firebase
		getPaymentsDetail(currentPayment.ID, c)
	}
}

func paymentsDetail(c *gin.Context) {

	getPaymentsDetail(currentPayment.ID, c)
}

func getPaymentsDetail(paymentID string, c *gin.Context) {

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Resp{}).
		SetError(Error{}).
		Get(baseURL + paymentPath + "/" + paymentID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	currentPayment = resp.Result().(*Resp)
	tempRef := resp.Result().(*Resp).Reference
	tempStatus := resp.Result().(*Resp).Status
	if err := paymentRef.Child(tempRef+"/status/"+tempStatus).Set(ctx, resp.Result()); err != nil {
		log.Fatalln("Error setting value:", err)
	}
	c.JSON(200, resp.Result())
}

func getEventNotifications(c *gin.Context) {

	eventID := c.Param("id")
	eventNotifications := c.Param("action")
	if eventNotifications == "/notifications" {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(Event{}).
			SetError(Error{}).
			Get(baseURL + eventsPath + "/" + eventID)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var notifications = resp.Result().(*Event).Notifications
		var notificationID = ""
		for _, notification := range notifications {
			if strings.Contains(*notification.URL, c.Request.Host) {
				notificationID = *notification.ID
			}
		}
		if len(notificationID) > 0 {
			resp, err := httpclient.R().
				SetHeader(authKey, secretKey).
				SetResult(Notification{}).
				SetError(Error{}).
				Get(baseURL + eventsPath + "/" + eventID + "/notifications/" + notificationID)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}
			c.JSON(200, resp.Result())
		} else {
			c.JSON(200, resp.Result())
		}
	} else {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(Event{}).
			SetError(Error{}).
			Get(baseURL + eventsPath + "/" + eventID)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.JSON(200, resp.Result())
	}
}

func getSubscribedWebhooks(c *gin.Context) {

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult([]Webhook{}).
		SetError(Error{}).
		Get(baseURL + webhooksPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func updateWebhookEvent(c *gin.Context) {

	webhookID := c.Param("id")
	action, _ := strconv.ParseBool(strings.Replace(c.Param("action"), "/", "", -1))
	body := make(map[string]bool)
	body["active"] = action
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetBody(body).
		SetResult(Webhook{}).
		SetError(Error{}).
		Patch(baseURL + webhooksPath + "/" + webhookID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func removeWebhookEvent(c *gin.Context) {
	webhookID := c.Param("id")
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Webhook{}).
		SetError(Error{}).
		Delete(baseURL + webhooksPath + "/" + webhookID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func getWebhookEventTypes(c *gin.Context) {

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult([]WebhookType{}).
		SetError(Error{}).
		SetQueryParams(map[string]string{
			"version": "2.0",
		}).
		Get(baseURL + eventTypesPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	currentEventType = string(resp.Body())
	data := &[]WebhookType{}
	error := json.Unmarshal([]byte(currentEventType), data)
	log.Println(error)
	log.Println((*data)[0].EventTypes)
	log.Println(currentEventType)
	c.JSON(200, resp.Result())
}

func updateWebhook(c *gin.Context) {
	webhookID := c.Param("id")

	type RequestBody struct {
		URL     string `json:"url"`
		Active  bool   `json:"active"`
		Headers string `json:"headers"`
	}
	var r RequestBody
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult([]WebhookType{}).
		SetError(Error{}).
		SetQueryParams(map[string]string{
			"version": "2.0",
		}).
		Get(baseURL + eventTypesPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	data := &[]WebhookType{}
	error := json.Unmarshal([]byte(string(resp.Body())), data)
	if error != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	log.Println("r.Active")
	log.Println(r.Active)
	webhook := &Webhook{
		URL:         &r.URL,
		ContentType: "json",
		Active:      &r.Active,
		Headers:     &WebhookHeader{Authorization: &r.Headers},
		EventTypes:  (*data)[0].EventTypes,
	}
	resp, respErr := httpclient.R().
		SetHeader(authKey, secretKey).
		SetBody(webhook).
		SetResult(Webhook{}).
		SetError(Error{}).
		Put(baseURL + webhooksPath + "/" + webhookID)
	if respErr != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func registerWebhook(c *gin.Context) {

	type RequestBody struct {
		URL string `json:"url,omitempty"`
	}
	var r RequestBody
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Println(r)
	url := r.URL + "/webhooks"
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult([]WebhookType{}).
		SetError(Error{}).
		SetQueryParams(map[string]string{
			"version": "2.0",
		}).
		Get(baseURL + eventTypesPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	data := &[]WebhookType{}
	error := json.Unmarshal([]byte(string(resp.Body())), data)
	if error != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	var activeBool = true
	webhook := &Webhook{
		URL:         &url,
		ContentType: "json",
		Active:      &activeBool,
		EventTypes:  (*data)[0].EventTypes,
	}
	resp, respErr := httpclient.R().
		SetHeader(authKey, secretKey).
		SetBody(webhook).
		SetResult(Webhook{}).
		SetError(Error{}).
		Post(baseURL + webhooksPath)
	if respErr != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func getWebhook(c *gin.Context) {

	webhookID := c.Param("id")
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Webhook{}).
		SetError(Error{}).
		Get(baseURL + webhooksPath + "/" + webhookID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func getDisputes(c *gin.Context) {

	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Disputes{}).
		SetError(Error{}).
		Get(baseURL + disputesPath)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func getDispute(c *gin.Context) {

	disputeID := c.Param("id")
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(Dispute{}).
		SetError(Error{}).
		Get(baseURL + disputesPath + "/" + disputeID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func uploadFile(c *gin.Context) {

	purpose := c.PostForm("purpose")
	form, err := c.MultipartForm()
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
		return
	}
	files := form.File["file"]
	filename := ""
	for _, file := range files {
		filename = filepath.Base(file.Filename)
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}
	}
	if len(filename) > 0 {
		resp, err := httpclient.R().
			SetFile("file", filename).
			SetFormData(map[string]string{
				"purpose": purpose,
			}).
			SetResult(File{}).
			Get(baseURL + filesPath)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.JSON(http.StatusOK, resp.Result())
		return
	}
	c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
}

func getFile(c *gin.Context) {

	fileID := c.Param("id")
	resp, err := httpclient.R().
		SetHeader(authKey, secretKey).
		SetResult(File{}).
		SetError(Error{}).
		Get(baseURL + filesPath + "/" + fileID)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.JSON(200, resp.Result())
}

func provideEvidence(c *gin.Context) {

	disputeID := c.Param("id")
	type RequestBody struct {
		Purpose string `json:"purpose,omitempty"`
		FileID  string `json:"file_id,omitempty"`
		Text    string `json:"text,omitempty"`
	}
	var r RequestBody
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(r.FileID) > 0 {
		body := map[string]string{
			r.Purpose + "_file": r.FileID,
			r.Purpose + "_text": r.Text,
		}
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetBody(body).
			SetResult(Dispute{}).
			SetError(Error{}).
			Put(baseURL + disputesPath + "/" + disputeID + "/evidence")
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.JSON(200, resp.Result())
	}
	c.Status(http.StatusBadRequest)
}

func postDisputeEvidence(c *gin.Context) {

	disputeID := c.Param("id")
	action := c.Param("action")
	if action == "/accept" {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(File{}).
			SetError(Error{}).
			Post(baseURL + disputesPath + "/" + disputeID + "/evidence")
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.JSON(200, resp.Result())
	}
	if action == "/evidence" {
		resp, err := httpclient.R().
			SetHeader(authKey, secretKey).
			SetResult(File{}).
			SetError(Error{}).
			Post(baseURL + disputesPath + "/" + disputeID + "/evidence")
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		c.JSON(200, resp.Result())
	}
}
