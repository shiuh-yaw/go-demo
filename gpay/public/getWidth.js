;
(
    function getWidth() {
        var tid
        //判断当前机器是否是 PC 端
        function IsPC() {
            //检测当前浏览器
            var userAgentInfo = navigator.userAgent;
            //机器数组
            var Agents = new Array(
                "Android",
                "iPhone",
                "SymbianOS",
                "Windows Phone",
                "iPad",
                "iPod"
            );
            var flag = true;
            for (var v = 0; v < Agents.length; v++) {
                //判断当前机器是否在 数组里存在
                if (userAgentInfo.indexOf(Agents[v]) > 0) {
                    flag = false;
                    break;
                }
            }
            return flag;
        }
        if (/(iPhone|iPad|iPod|iOS|Android)/i.test(navigator.userAgent)) {
            console.log(1);
            document.body.style.height = window.innerHeight + "px";

            function recalcPhone() {
                //获取屏幕宽度
                var clientWidth = document.documentElement.clientWidth;
                if (!clientWidth) return;
                //动态设置根节点的字体大小
                document.documentElement.style.fontSize =
                    40 * (clientWidth / 750) + "px";
            }

            function initRecalcPhone() {
                recalcPhone();
                var resizeEvt =
                    "osrientationchange" in window ?
                    "orientationchange" :
                    "resize";
                if (!document.addEventListener) return;
                window.addEventListener(resizeEvt, recalcPhone, false);
                document.addEventListener(
                    "DOMContentLoaded",
                    recalcPhone,
                    false
                );
            }

            initRecalcPhone()
        } else {
            //如果不是移动端 就为PC端
            document.body.style.height = window.innerHeight + "px";

            function recalcPc() {
                var clientWidth = document.documentElement.clientWidth;
                if (!clientWidth) return;
                document.documentElement.style.fontSize =
                    40 * (clientWidth / 1920) + "px";
            }

            function initRecalcPc() {
                recalcPc();
                var resizeEvt =
                    "osrientationchange" in window ?
                    "orientationchange" :
                    "resize";
                if (!document.addEventListener) return;
                window.addEventListener(resizeEvt, recalcPc, false);
                document.addEventListener(
                    "DOMContentLoaded",
                    recalcPc,
                    false
                );
            }
            initRecalcPc();
        }
    }
)();