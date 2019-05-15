var config = require('../config')
var log = require('../log')

var mongoose = require('mongoose')
var bcrypt = require('bcrypt')
var crypto = require('crypto')
var nodemailer = require('nodemailer')

var user = mongoose.Schema({
    login: String,
    password: String,
    email: String,

    activation: {
        activated: { type: Boolean, default: false },
        token: { type: String },
        expires: { type: Number }
    }
})

user.methods.isValidPassword = function (password) {
    return bcrypt.compareSync(password, this.password)
}

user.methods.setPassword = function (password) {
    this.password = bcrypt.hashSync(password, bcrypt.genSaltSync(8))
}

user.methods.initActivation = function (callback) {

    var a = this.activation
    if(config.disableMail)
    {
        a.activated = true
        callback(true)
        return
    }

    a.activated = false
    a.token = crypto.randomBytes(32).toString('hex')
    //TODO
    a.expires = 0

    var transporter = nodemailer.createTransport(config.mailConfig)

    var mailOptions = {
        from: '"StickArena" <' + config.mailConfig.auth.user + '>',
        to: this.email,
        subject: 'Rejestracja w StickArena',
        text: `Tej,
        Aby aktywować konto kliknij w poniższy link:
        https://kosert.me/stickarena/activate?token=${a.token}
        
        Lub zaloguj się i wpisz poniższy kod:
        ${a.token}
        
        Pozdro 600
        Zespół StickArena`,
        html: `Tej,<br>
        Aby aktywować konto kliknij w poniższy link:<br>
        <a href="https://kosert.me/stickarena/activate?token=${a.token}">https://kosert.me/stickarena/activate?token=${a.token}</a><br>
        <br>
        Lub zaloguj się i wpisz poniższy kod:<br>
        ${a.token}<br>
        <br>
        Pozdro 600<br>
        Zespół StickArena<br>`,
    }

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            log.error(error)
            callback(false)
        }
        else
        {
            log.info('Message sent to: ' + this.email)
            callback(true)
        }
    })
}

module.exports = mongoose.model('User', user)