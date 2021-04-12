var allowedPaymentMethods = ['CARD', 'TOKENIZED_CARD'];
var allowedCardNetworks = ['MASTERCARD', 'VISA'];
var allowedAuthMethods = ["CRYPTOGRAM_3DS"];
var tokenizationParameters = {
    tokenizationType: 'PAYMENT_GATEWAY',
    parameters: {
        'gateway': 'checkoutltd',
        'gatewayMerchantId': 'pk_test_4d9ec2b1-4659-449b-9eb9-fdce5069c308'
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
	$.ajax({
        url: "../pay/getCheckoutProdcut",
        type: 'post',
        data: {"appId": appId, "productName": productId},
        async:false,
        success: function (result) {
             price = result.data.price;
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
        },
        error: function () {
            console.log("get roleinfo failed!");
        }
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
        merchantId: 'BCR2DN6TT6UKLQRM',
        paymentMethodTokenizationParameters: tokenizationParameters,
        allowedPaymentMethods: allowedPaymentMethods,
        cardRequirements: {
            allowedAuthMethods: allowedAuthMethods,
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
        currencyCode: 'USD',
        totalPriceStatus: 'FINAL',
        // set to cart total
        totalPrice: price
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
        currencyCode: 'USD'
    };
    var paymentsClient = getGooglePaymentsClient();
    paymentsClient.prefetchPaymentData(paymentDataRequest);
}

/**
 * Show Google Pay chooser when Google Pay purchase button is clicked
 */
function onGooglePaymentButtonClicked() {
	createGooglePay();
	
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
        var payment1 = paymentData.paymentMethodToken.token;
        $.ajax({
			url:'/platform/pay/checkoutGoogleCallback',
			type:'post',
			data:{"googleToken":payment1,"orderId":orderId,"locale":locale},
			success:function(res){
				if(res.ret == 0){
					 resolve(setTimeout("window.location.href = '" + res.data.url + "'",500));
				}else{
					 reject(setTimeout("window.location.href = '" + res.data.url + "'",500));
				}
			},
		error:function(){
			  reject({});
	    }
        });
    });

}