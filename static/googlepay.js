var allowedPaymentMethods = ['CARD', 'TOKENIZED_CARD'];
var allowedCardNetworks = ['MASTERCARD', 'VISA'];

var tokenizationParameters = {
    tokenizationType: 'PAYMENT_GATEWAY',
    parameters: {
        'gateway': 'checkoutltd',
        'gatewayMerchantId': 'pk_test_8a3d22b3-5684-4c25-9b21-1fa98776225c'
    }
}

/**
 * Initialize a Google Pay API client
 *
 * @returns {google.payments.api.PaymentsClient} Google Pay API client
 */
function getGooglePaymentsClient() {
    return (new google.payments.api.PaymentsClient({ environment: 'TEST' }));
}

/**
 * Initialize Google PaymentsClient after Google-hosted JavaScript has loaded
 */
function onGooglePayLoaded() {
    var paymentsClient = getGooglePaymentsClient();
    paymentsClient.isReadyToPay({ allowedPaymentMethods: allowedPaymentMethods })
        .then(function (response) {
            if (response.result) {
                addGooglePayButton();
                prefetchGooglePaymentData();
            }
        })
        .catch(function (err) {
            // show error in developer console for debugging
            console.error(err);
        });
}

/**
 * Add a Google Pay purchase button alongside an existing checkout button
 *
 * @see {@link https://developers.google.com/pay/api/web/guides/brand-guidelines|Google Pay brand guidelines}
 */
function addGooglePayButton() {
    const paymentsClient = getGooglePaymentsClient();
    const button = paymentsClient.createButton({ onClick: onGooglePaymentButtonClicked });
    document.getElementById('google-pay-container').appendChild(button);
}

/**
 * Configure support for the Google Pay API
 *
 * @see {@link https://developers.google.com/pay/api/web/reference/object#PaymentDataRequest|PaymentDataRequest}
 * @returns {object} PaymentDataRequest fields
 */
function getGooglePaymentDataConfiguration() {
    return {
        // @todo a merchant ID is available for a production environment after approval by Google
        // @see {@link https://developers.google.com/pay/api/web/guides/test-and-deploy/overview|Test and deploy}
        merchantId: '01234567890123456789',
        paymentMethodTokenizationParameters: tokenizationParameters,
        allowedPaymentMethods: allowedPaymentMethods,
        cardRequirements: {
            allowedCardNetworks: allowedCardNetworks
        }
    };
}

/**
 * Provide Google Pay API with a payment amount, currency, and amount status
 *
 * @see {@link https://developers.google.com/pay/api/web/reference/object#TransactionInfo|TransactionInfo}
 * @returns {object} transaction info, suitable for use as transactionInfo property of PaymentDataRequest
 */
function getGoogleTransactionInfo() {
    return {
        currencyCode: 'SGD',
        totalPriceStatus: 'FINAL',
        // set to cart total
        totalPrice: '10.00'
    };
}

/**
 * Prefetch payment data to improve performance
 */
function prefetchGooglePaymentData() {
    var paymentDataRequest = getGooglePaymentDataConfiguration();
    // transactionInfo must be set but does not affect cache
    paymentDataRequest.transactionInfo = {
        totalPriceStatus: 'NOT_CURRENTLY_KNOWN',
        currencyCode: 'SGD'
    };
    var paymentsClient = getGooglePaymentsClient();
    paymentsClient.prefetchPaymentData(paymentDataRequest);
}

/**
 * Show Google Pay chooser when Google Pay purchase button is clicked
 */
function onGooglePaymentButtonClicked() {
    var paymentDataRequest = getGooglePaymentDataConfiguration();
    paymentDataRequest.transactionInfo = getGoogleTransactionInfo();

    var paymentsClient = getGooglePaymentsClient();
    paymentsClient.loadPaymentData(paymentDataRequest)
        .then(function (paymentData) {
            // handle the response
            processPayment(paymentData);
        })
        .catch(function (err) {
            // show error in developer console for debugging
            console.error(err);
        });
}

/**
 * Process payment data returned by the Google Pay API
 *
 * @param {object} paymentData response from Google Pay API after shopper approves payment
 * @see {@link https://developers.google.com/pay/api/web/reference/object#PaymentData|PaymentData object reference}
 */
function processPayment(paymentData) {

    return new Promise(function (resolve, reject) {
        console.log(JSON.parse(paymentData.paymentMethodToken.token));
        const payment = {
            signature: JSON.parse(paymentData.paymentMethodToken.token).signature,
            protocolVersion: JSON.parse(paymentData.paymentMethodToken.token).protocolVersion,
            signedMessage: JSON.parse(paymentData.paymentMethodToken.token).signedMessage,
        };
        console.log(payment);
        var r = new XMLHttpRequest();
        r.open("POST", "/processGooglePayResponse");
        r.onreadystatechange = function () {
            if (r.readyState != 4) {
                return;
            }
            if (r.status != 200) {
                reject({});
            }
            resolve({});
        }
        r.setRequestHeader("Content-Type", "application/json");
        r.send(JSON.stringify(payment));
    });

}