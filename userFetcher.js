const User = require('./models/user')
const log = require('./log')

module.exports = {

    getFullUser: function (login) {
        return new Promise(function (resolve, reject) {
            User.findOne({ 'login': login }, (err, res) => {
                if (err) {
                    log.error(err)
                    reject(err)
                }
                else if (!res)
                    reject("Użytkownik nie istnieje: " + login)
                else
                    resolve(res)
            })
        })
    }
}