/*
 Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See LICENSE.txt for this sample’s licensing information

 Abstract:
 The main client-side JS. Handles displaying the Apple Pay button and requesting a payment.
 */


var payButton = document.getElementById("pay-button");
var form = document.getElementById("payment-form");
var pk = "pk_test_8a3d22b3-5684-4c25-9b21-1fa98776225c";
var cartToken = document.getElementById("token");

Frames.init({
    publicKey: cartToken.value,
    style: {
        base: {
            // color: "black",
            fontSize: "18px",
            fontWeight: "500",
            transition: "none",
        },
        placeholder: {
            base: {
                fontSize: "14px",
            },
        },
    },
});

Frames.addEventHandler(Frames.Events.FRAME_ACTIVATED, onActivated);
function onActivated(event) {
    console.log(event);
}

Frames.addEventHandler(Frames.Events.READY, onReady);
function onReady(event) {
    console.log(event);
}

var logos = generateLogos();
function generateLogos() {
    var logos = {};
    logos["card-number"] = {
        src: "card",
        alt: "card number logo",
    };
    logos["expiry-date"] = {
        src: "exp-date",
        alt: "expiry date logo",
    };
    logos["cvv"] = {
        src: "cvv",
        alt: "cvv logo",
    };
    return logos;
}

var errors = {};
errors["card-number"] = "Please enter a valid card number";
errors["expiry-date"] = "Please enter a valid expiry date";
errors["cvv"] = "Please enter a valid cvv code";

Frames.addEventHandler(
    Frames.Events.FRAME_VALIDATION_CHANGED,
    onValidationChanged
);
function onValidationChanged(event) {
    var e = event.element;

    if (event.isValid || event.isEmpty) {
        if (e === "card-number" && !event.isEmpty) {
            showPaymentMethodIcon();
        }
        // setDefaultIcon(e);
        // clearErrorIcon(e);
        clearErrorMessage(e);
    } else {
        if (e === "card-number") {
            clearPaymentMethodIcon();
        }
        // setDefaultErrorIcon(e);
        // setErrorIcon(e);
        setErrorMessage(e);
    }
}

function clearErrorMessage(el) {
    var selector = ".error-message__" + el;
    var message = document.querySelector(selector);
    message.textContent = "";
}

function clearErrorIcon(el) {
    var logo = document.getElementById("icon-" + el + "-error");
    logo.style.removeProperty("display");
}

function showPaymentMethodIcon(parent, pm) {
    console.log("CARD NAME parent: %o", parent);
    if (parent) parent.classList.add("show");

    var logo = document.getElementById("logo-payment-method");
    if (pm) {
        var name = pm.toLowerCase();
        console.log("CARD NAME: %o", name);
        logo.setAttribute("src", "/images/" + name + ".svg");
        logo.setAttribute("alt", pm || "payment method");
    }
    logo.style.removeProperty("display");
}

function clearPaymentMethodIcon(parent) {
    if (parent) parent.classList.remove("show");

    var logo = document.getElementById("logo-payment-method");
    logo.style.setProperty("display", "none");
}

function setErrorMessage(el) {
    var selector = ".error-message__" + el;
    var message = document.querySelector(selector);
    message.textContent = errors[el];
}

function setDefaultIcon(el) {
    var selector = "icon-" + el;
    var logo = document.getElementById(selector);
    logo.setAttribute(
        "src",
        "/images/" + logos[el].src + ".svg"
    );
    logo.setAttribute("alt", logos[el].alt);
}

function setDefaultErrorIcon(el) {
    var selector = "icon-" + el;
    var logo = document.getElementById(selector);
    logo.setAttribute(
        "src",
        "/images/" + logos[el].src + "-error.svg"
    );
    logo.setAttribute("alt", logos[el].alt);
}

function setErrorIcon(el) {
    var logo = document.getElementById("icon-" + el + "-error");
    logo.style.setProperty("display", "block");
}

Frames.addEventHandler(
    Frames.Events.CARD_VALIDATION_CHANGED,
    cardValidationChanged
);
function cardValidationChanged(event) {
    payButton.disabled = !Frames.isCardValid();
}

Frames.addEventHandler(
    Frames.Events.CARD_TOKENIZATION_FAILED,
    onCardTokenizationFailed
);
function onCardTokenizationFailed(error) {
    console.log("CARD_TOKENIZATION_FAILED: %o", error);
    Frames.init();
    Frames.enableSubmitForm();
}

Frames.addEventHandler(Frames.Events.CARD_TOKENIZED, onCardTokenized);
function onCardTokenized(event) {
    console.log("onCardTokenized Event: %o", event);
    Frames.addCardToken(form, event.token);
    form.submit();
}

Frames.addEventHandler(
    Frames.Events.PAYMENT_METHOD_CHANGED,
    paymentMethodChanged
);
function paymentMethodChanged(event) {
    var pm = event.paymentMethod;
    let container = document.querySelector(".payment-method");
    if (!pm) {
        clearPaymentMethodIcon(container);
    } else {
        // clearErrorIcon("card-number");
        showPaymentMethodIcon(container, pm);
    }
}

Frames.addEventHandler(Frames.Events.CARD_SUBMITTED, function () {
    payButton.disabled = true;
    // display loader
});

form.addEventListener("submit", onSubmit);
function onSubmit(event) {
    event.preventDefault();
    var name = document.getElementById("name").value;
    Frames.cardholder = {
        name: name,
    };
    Frames.submitCard();
}
/**
 * This method is called when the page is loaded.
 * We use it to show the Apple Pay button as appropriate.
 * Here we're using the ApplePaySession.canMakePayments() method,
 * which performs a basic hardware check.
 *
 * If we wanted more fine-grained control, we could use
 * ApplePaySession.canMakePaymentsWithActiveCards() instead.
 */
document.addEventListener('DOMContentLoaded', function () {
    if (window.ApplePaySession) {
        if (ApplePaySession.canMakePayments) {
            showApplePayButton();
        }
    }
});

function showApplePayButton() {
    HTMLCollection.prototype[Symbol.iterator] = Array.prototype[Symbol.iterator];
    const buttons = document.getElementsByClassName("apple-pay-button");
    for (let button of buttons) {
        button.className += " visible";
    }
}


/**
 * Apple Pay Logic
 * Our entry point for Apple Pay interactions.
 * Triggered when the Apple Pay button is pressed
 */
function applePayButtonClicked() {
    const paymentRequest = {
        countryCode: 'SG',
        currencyCode: 'SGD',
        shippingMethods: [
            {
                label: 'Free Shipping',
                amount: '0.00',
                identifier: 'free',
                detail: 'Delivers in five business days',
            },
            {
                label: 'Express Shipping',
                amount: '0.49',
                identifier: 'express',
                detail: 'Delivers in two business days',
            },
        ],

        lineItems: [
            {
                label: 'Shipping',
                amount: '0.00',
            }
        ],

        total: {
            label: 'Apple Pay Example',
            amount: '0.00',
        },

        supportedNetworks: ['amex', 'discover', 'masterCard', 'visa'],
        merchantCapabilities: ['supports3DS'],

        requiredShippingContactFields: ['email'],
    };

    const session = new ApplePaySession(1, paymentRequest);

    /**
     * Merchant Validation
     * We call our merchant session endpoint, passing the URL to use
     */
    session.onvalidatemerchant = (event) => {
        console.log("Validate merchant");
        const validationURL = event.validationURL;
        getApplePaySession(event.validationURL).then(function (response) {
            console.log(response);
            session.completeMerchantValidation(response);
        });
    };

    /**
     * Shipping Method Selection
     * If the user changes their chosen shipping method we need to recalculate
     * the total price. We can use the shipping method identifier to determine
     * which method was selected.
     */
    session.onshippingmethodselected = (event) => {
        const shippingCost = event.shippingMethod.identifier === 'free' ? '0.00' : '0.49';
        const totalCost = event.shippingMethod.identifier === 'free' ? '0.01' : '0.50';

        const lineItems = [
            {
                label: 'Shipping',
                amount: shippingCost,
            },
        ];

        const total = {
            label: 'Apple Pay Example',
            amount: totalCost,
        };

        session.completeShippingMethodSelection(ApplePaySession.STATUS_SUCCESS, total, lineItems);
    };

    /**
     * Payment Authorization
     * Here you receive the encrypted payment data. You would then send it
     * on to your payment provider for processing, and return an appropriate
     * status in session.completePayment()
     */
    session.onpaymentauthorized = (event) => {
        // Send payment for processing...
        const payment = event.payment;
        console.log(payment);
        var r = new XMLHttpRequest();
        r.open("POST", "/processApplePayResponse");
        r.onreadystatechange = function () {
            if (r.readyState != 4) {
                return;
            }
            if (r.status != 200) {
                session.completePayment(ApplePaySession.STATUS_FAILURE);
            }
            session.completePayment(ApplePaySession.STATUS_SUCCESS);
        }
        r.setRequestHeader("Content-Type", "application/json");
        r.send(JSON.stringify(payment));
    }

    // All our handlers are setup - start the Apple Pay payment
    session.begin();
}
