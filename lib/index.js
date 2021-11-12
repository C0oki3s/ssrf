const dns = require('dns')
const Parser = require('url')
const fs = require('fs')
const ipAddress = require('ipaddr.js')
const ssrf = {}

let Forntend_Input
let Destruct_URL
let Sanitize
const user_blacklist = []
let user_path = true

ssrf.options = ({
  blacklist, /** Take's input Absolute path like(/usr/blacklist/urls.txt) */
  path
}) => {
  if (blacklist != undefined) {
    try {
      const data = fs.readFileSync(blacklist).toString().replace(/\r\n/g, '\n').split('\n')
      /**
             *  @data consist of user supplied host name's
             *  Ex: google.com\n mail.google.com\n
             */

      for (i in data) {
        user_blacklist.push(data[i]) // pushing to a global array object {user_blacklist}
      }
    } catch (error) {
      throw new Error('File does not Exists')
    }
  }
  if (path != undefined) {
    user_path = path
  }
}

ssrf.url = async (url) => {
  Forntend_Input = url

  /**
         * Forntend_input will be configured by user which is input's name parameter
         * need to supply -> ssrf.url(req.body.url)
        */
  await SanitizeURl(Forntend_Input)

  /**
         * Calling SanitizeURL
         * where SanitizeURL will Set a global variable of Destructed url
        */

  const blacklist_ssrf = await CheckBlacklist()
  /**
         * blacklist_ssrf will be error handler in main function if blacklist_ssrf
         * have length grater than 0 it will set a to req global object
        */

  if (blacklist_ssrf) {
    throw new Error(JSON.stringify(blacklist_ssrf))

  } else {
    if (user_path == false) {
      return `${Destruct_URL.protocol}//${Destruct_URL.hostname}`
    } else {
      return Destruct_URL.href
    }
    /**
             * Setting Sanitize input to req.object
             * By default req.Sanitize return's Absolute URl including path and parameters
             * To only return hostname user need to set path:false in ssrf.options({})
            */
  }
  // }
}

const SanitizeURl = (url) => {
  const re = /[^@]/
  if (re.test(url)) {
    Sanitize = url?.split('@')[0].toString()
  }
  /**
     * Sanitize variable Contains url after sanitization
     * where this module only takes first part of the hostname
     * if user send's https://google.com@attacker.com
     * this module parse first hostname as google.com
     */
  Destruct_URL = Parser.parse(Sanitize, true)
  // console.log(Destruct_URL.hostname)
  /*
    *  Destruct_URL Contains parts of url Example url:https://google.com?a=1
    *  Destruct_URL.hostname = google
    *  (url) module https://nodejs.org/api/url.html
    */
}

const CheckIp = (ip) => {
  if (!ipAddress.isValid(ip)) {
    return true
  }
  try {
    const address = ipAddress.parse(ip)
    const range = address.range()
    if (range !== 'unicast') {
      return false
      /**
         * Block's every private network IP For more ref to
         * https://www.npmjs.com/package/ipaddr.js/v/1.1.0
        */
    }
  } catch (err) {
    return false
  }
  return true
}

const CheckSchema = () => {
  /**
     * This tool Only allow http and https Schema
    */

  if (Destruct_URL.protocol == 'http:') {
    return true
  } else if (Destruct_URL.protocol == 'https:') {
    return true
  } else {
    return false
  }
}

const CheckBlacklist = async () => {
  const Catch = []
  /**
     * value contains Boolean value which return from CheckSchema function
     * if it is http ot https its return true else false then throw Append Error
    */
  const value = CheckSchema()

  if (!value) {
    Catch.push({ ssrf: 'Schema Error' })
  }
  /**
     * After every condition we will Check if there is an Error dangling
     * in Catch Array if any Object Alredy Present in Catch
     * we will return and Dont go Forward
    */
  if (Catch.length) {
    return Catch
  }

  user_blacklist?.forEach((host) => {
    /**
         * if any blacklist passed by user We will check here
         * where host contains user supplied hostnames and if
         * any of them Matchs with End user input will return
         * Error
        */
    if (host == Destruct_URL.hostname) {
      Catch.push({ ssrf: 'Blacklist Error' })
    }
  })

  if (Catch.length) {
    return Catch
  }

  try {
    const lookup_return = await lookup() // contains ip address
    /**
         * CheckIp prevent DNS rebinding attack
        */
    const result = CheckIp(lookup_return)
    if (!result) {
      Catch.push({ ssrf: 'Private IP Lookup' })
    }
  } catch (error) {
    Catch.push({ ssrf: 'Catch Block' })
  }
  if (Catch.length) {
    return Catch
  }
}

async function lookup () {
  const options = {
    family: 4,
    hints: dns.ADDRCONFIG | dns.V4MAPPED
  }
  return new Promise((resolve, reject) => {
    dns.lookup(Destruct_URL.hostname, options, (err, address, family) => {
      if (err) reject(err)
      resolve(address)
    })
  })
};

module.exports = ssrf
