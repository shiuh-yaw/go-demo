// A reference to Stripe.js
var channel = GetQueryString("channel");
var appId = GetQueryString("appId");
var locale = GetQueryString("locale");
var serverId = GetQueryString("serverId");
var roleName = GetQueryString("roleName");
var productId = GetQueryString("productId");
var productNumber = GetQueryString("productNumber");
var platform = GetQueryString("platform");
var reg1 = new RegExp("1zuokuohao1","g")
var reg2 = new RegExp("1youkuohao1","g")
var extra1 = GetQueryString("extra1").replace(reg1,"{").replace(reg2,"}");
var extra2 = GetQueryString("extra2");
var errorCode = GetQueryString("errorCode");
var userId;
var price;
var orderId;
var appleToken;

$(function () {
	if(0 != errorCode){
		$("#all").empty().append("error : "+errorCode);
		return;
	}
    var attention = $(".attention");
    if ("zh-Hant" == locale) {
        // 清空数据
        attention.text("");
        // 添加html内容，不能用Text 或Val
        attention.append("請在支付前確認，本平台不接受退款，<br/>點擊檔位進行儲值視為同意本條。");
    } else {
        // 清空数据
        attention.text("");
        attention.append("We do not accept refunds. If you do agree, please continue finishing further payment; otherwise, please close this page to deny.");   //添加html内容，不能用Text 或Val
    }
});

function getPrice(){
	$.ajax({
        url: "../pay/getCheckoutProdcut",
        type: 'post',
        data: {"appId": appId, "productName": productId},
        async:false,
        success: function (result) {
             price = result.data.price;
        },
        error: function () {
            console.log("get roleinfo failed!");
        }
    });
}

function createApplePay(){
	
	if(!$("#policybox1").get(0).checked){
		$("#message").html("Please accept T&C and the refund policy");
		return;
	}
	
	$.ajax({
        url: "../pay/getRoleInfo",
        type: 'post',
        data: {"name": roleName, "serverId": serverId, "appId": appId},
        async:false,
        success: function (result) {
        	 console.info(result);
             var res = result.data;
             res = res.roleInfo;
             if (0 != res.err_Code && !res.roleId) {
                 alert("Please check the role information");
             }

             userId = res.roleId;	
             var data = {
                     "userId": userId, "appId": appId,
                     "locale": locale, "serverId": serverId, "roleName": roleName, "productName": productId, "payType":platform ,
                     "extra1": extra1, "extra2": extra2
                 };
             $.ajax({
                 url: "../pay/checkoutCreateAppleOrder",
                 type: 'post',
                 data: data,
                 async:false,
                 success: function (res) {
                	 orderId = res.orderId;
                	 appleToken = JSON.parse(res.data.result);
                 },
                 error: function () {
                     console.log("checkout create order failed!");
                 }
             });
        },
        error: function () {
            console.log("get roleinfo failed!");
        }
    });
}

function createGooglePay(){
	$.ajax({
        url: "../pay/getRoleInfo",
        type: 'post',
        data: {"name": roleName, "serverId": serverId, "appId": appId},
        async:false,
        success: function (result) {
        	 console.info(result);
             var res = result.data;
             res = res.roleInfo;
             if (0 != res.err_Code && !res.roleId) {
                 alert("Please check the role information");
             }

             userId = res.roleId;	
             var data = {
                     "userId": userId, "appId": appId,
                     "locale": locale, "serverId": serverId, "roleName": roleName, "productName": productId, "payType":platform ,
                     "extra1": extra1, "extra2": extra2
                 };
             $.ajax({
                 url: "../pay/checkoutCreateGoogleOrder",
                 type: 'post',
                 data: data,
                 async:false,
                 success: function (res) {
                	 orderId = res.orderId;
                	 return res.data.result;
                 },
                 error: function () {
                     console.log("checkout create order failed!");
                 }
             });
        },
        error: function () {
            console.log("get roleinfo failed!");
        }
    });
}

function createCardPay(){
	if(!$("#policybox1").get(0).checked){
		$("#message").html("Please accept T&C and the refund policy");
		return;
	}
	
	$.ajax({
        url: "../pay/getRoleInfo",
        type: 'post',
        data: {"name": roleName, "serverId": serverId, "appId": appId},
        async:false,
        success: function (result) {
        	 console.info(result);
             var res = result.data;
             res = res.roleInfo;
             if (0 != res.err_Code && !res.roleId) {
                 alert("Please check the role information");
             }

             userId = res.roleId;	
             var data = {
                     "userId": userId, "appId": appId,
                     "locale": locale, "serverId": serverId, "roleName": roleName, "productName": productId, "payType":platform ,
                     "extra1": extra1, "extra2": extra2
                 };
             $.ajax({
                 url: "../pay/checkoutCreateWebOrder",
                 type: 'post',
                 data: data,
                 async:false,
                 success: function (res) {
                	 window.location.href = res.url;
                 },
                 error: function () {
                     console.log("checkout create order failed!");
                 }
             });
        },
        error: function () {
            console.log("get roleinfo failed!");
        }
    });
}

function GetQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return decodeURI(r[2]);
    return null;
}

	 