window.onload = function () {

    var emailOk = false
    var loginOk = false
    var passwordsOk = false
    var termsOk = false

    var registerButton = document.getElementById('registerButton')
    registerButton.addEventListener('click', register)

    var loginButton = document.getElementById('loginButton')
    loginButton.addEventListener('click', login)

    var registerEmail = document.getElementById('registerEmail')
    registerEmail.addEventListener('keyup', callCheckEmail)
    registerEmail.addEventListener('paste', callCheckEmail)

    var registerLogin = document.getElementById('registerLogin')
    registerLogin.addEventListener('keyup', callCheckLogin)
    registerLogin.addEventListener('paste', callCheckLogin)

    var registerPassword = document.getElementById('registerPassword')
    var repeatPassword = document.getElementById('repeatPassword')

    registerPassword.addEventListener('keyup', callCheckPasswords)
    registerPassword.addEventListener('paste', callCheckPasswords)

    repeatPassword.addEventListener('keyup', callCheckPasswords)
    repeatPassword.addEventListener('paste', callCheckPasswords)

    var registerTerms = document.getElementById('registerTerms')
    registerTerms.addEventListener('change', function () {
        checkTerms()
    })

    checkEmail()
    checkLogin()
    checkPasswords()
    checkTerms()

    document.getElementById('login').addEventListener('keypress', function (e) {
        if (e.keyCode === 13) {
            loginButton.click()
        }
    })
    document.getElementById('password').addEventListener('keypress', function (e) {
        if (e.keyCode === 13) {
            loginButton.click()
        }
    })

    setTimeout(function () {
        if (detect())
            window.location.href = "selenium_detected.jpg"
    }, 2000)

    function callCheckEmail() {
        setTimeout(checkEmail, 0)
    }

    function checkEmail() {
        var registerEmail = document.getElementById('registerEmail')
        if (registerEmail.value)
            emailOk = true
        else
            emailOk = false
        refreshRegisterButton()
    }

    function callCheckLogin() {
        setTimeout(checkLogin, 0)
    }

    function checkLogin() {
        var registerLogin = document.getElementById('registerLogin')
        if (registerLogin.value && registerLogin.value.length > 1) {
            loginOk = true
            document.getElementById('loginError').hidden = true
        }
        else {
            loginOk = false
            document.getElementById('loginError').hidden = false
        }
        refreshRegisterButton()
    }

    function checkTerms() {
        termsOk = registerTerms.checked

        var termsError = document.getElementById('termsError')
        if (termsOk)
            termsError.hidden = true
        else
            termsError.hidden = false

        refreshRegisterButton()
    }

    function callCheckPasswords() {
        setTimeout(checkPasswords, 0)
    }

    function checkPasswords() {
        var passwordError = document.getElementById('passwordError')
        var repeatError = document.getElementById('repeatError')

        passwordError.hidden = true
        repeatError.hidden = true

        var registerPassword = document.getElementById('registerPassword')
        var repeatPassword = document.getElementById('repeatPassword')

        var registerButton = document.getElementById('registerButton')

        if (registerPassword.value.length < 8) {
            passwordError.hidden = false
            passwordsOk = false
            refreshRegisterButton()
            return
        }

        if (registerPassword.value != repeatPassword.value) {
            repeatError.hidden = false
            passwordsOk = false
            refreshRegisterButton()
            return
        }

        passwordsOk = true
        refreshRegisterButton()
    }

    function refreshRegisterButton() {
        var registerButton = document.getElementById('registerButton')

        if (emailOk && loginOk && passwordsOk && termsOk) {
            registerButton.disabled = false
        }
        else
            registerButton.disabled = true
    }

    function register() {

        document.getElementById('alertRegister').hidden = true
        document.getElementById('registerButton').disabled = true
        var form = document.getElementById('registerForm')
        var inputs = form.getElementsByTagName('input')

        var formData = {}
        for (var i = 0; i < inputs.length; i++) {
            formData[inputs[i].id] = inputs[i].value
        }

        var json = JSON.stringify(formData)
        var xmlhttp = new XMLHttpRequest()
        xmlhttp.open("POST", "register", true)
        xmlhttp.setRequestHeader("Content-Type", "application/json")
        xmlhttp.responseType = "json"
        xmlhttp.onreadystatechange = function () {
            if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
                handleRegisterResponse(xmlhttp.response)
            }
        }
        xmlhttp.send(json)
    }

    function handleRegisterResponse(res) {
        if (res.error) {
            setTimeout(function () {
                var alert = document.getElementById('alertRegister')
                alert.innerText = "Błąd: " + res.error
                alert.hidden = false
                document.getElementById('registerButton').disabled = false
            }, 500)
        }
        else {
            window.location.href = '.'
        }
    }

    function login() {
        document.getElementById('alertLogin').hidden = true
        document.getElementById('loginButton').disabled = true
        var form = document.getElementById('loginForm')
        var inputs = form.getElementsByTagName('input')

        var formData = {}
        for (var i = 0; i < inputs.length; i++) {
            formData[inputs[i].id] = inputs[i].value
        }

        var json = JSON.stringify(formData)
        var xmlhttp = new XMLHttpRequest()
        xmlhttp.open("POST", "login", true)
        xmlhttp.setRequestHeader("Content-Type", "application/json")
        xmlhttp.responseType = "json"
        xmlhttp.onreadystatechange = function () {
            if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
                handleLoginResponse(xmlhttp.response)
            }
        }
        xmlhttp.send(json)
    }

    function handleLoginResponse(res) {
        if (res.error) {
            setTimeout(function () {
                var alert = document.getElementById('alertLogin')
                alert.innerText = "Błąd: " + res.error
                alert.hidden = false
                document.getElementById('loginButton').disabled = false
            }, 500)
        }
        else {
            window.location.href = '.'
        }
    }

    function detect() {
        var documentDetectionKeys = [
            "__webdriver_evaluate",
            "__selenium_evaluate",
            "__webdriver_script_function",
            "__webdriver_script_func",
            "__webdriver_script_fn",
            "__fxdriver_evaluate",
            "__driver_unwrapped",
            "__webdriver_unwrapped",
            "__driver_evaluate",
            "__selenium_unwrapped",
            "__fxdriver_unwrapped",
        ];

        var windowDetectionKeys = [
            "_phantom",
            "__nightmare",
            "_selenium",
            "callPhantom",
            "callSelenium",
            "_Selenium_IDE_Recorder",
        ];

        for (const windowDetectionKey in windowDetectionKeys) {
            const windowDetectionKeyValue = windowDetectionKeys[windowDetectionKey];
            if (window[windowDetectionKeyValue]) {
                return true;
            }
        };
        for (const documentDetectionKey in documentDetectionKeys) {
            const documentDetectionKeyValue = documentDetectionKeys[documentDetectionKey];
            if (window['document'][documentDetectionKeyValue]) {
                return true;
            }
        };

        for (const documentKey in window['document']) {
            if (documentKey.match(/\$[a-z]dc_/) && window['document'][documentKey]['cache_']) {
                return true;
            }
        }

        if (window['external'] && window['external'].toString() && (window['external'].toString()['indexOf']('Sequentum') != -1)) return true;

        if (window['document']['documentElement']['getAttribute']('selenium')) return true;
        if (window['document']['documentElement']['getAttribute']('webdriver')) return true;
        if (window['document']['documentElement']['getAttribute']('driver')) return true;

        return false;
    };
}

