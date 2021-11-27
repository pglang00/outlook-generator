const request = require('request')
const fs = require('fs')
var random_name = require('node-random-name');
var genCipher = require('./cipher');
const password = require('secure-random-password');
const colors = require('colors')
const { Webhook, MessageBuilder } = require('discord-webhook-node');

class Outlook {
    constructor(task) {
        this.id = task.id + 1
        this.webhook = new Webhook(task.webhook)
        this.captchaLimit = task.limit
        this.key = task.key
        const rawProx = task.proxyList

        this.proxies = []

        rawProx.forEach(raw => {
            let split = raw.split(':');
            this.proxies.push(`http://${split[2]}:${split[3]}@${split[0]}:${split[1]}`)
        })

        let email = random_name().replace(' ','')
        this.email = email.toLowerCase() + this.rNum(1, 100000).toString()
        this.pw = this.randPw()
        this.jar = request.jar()
        this.proxy = this.proxies[this.rNum(0, this.proxies.length - 1)]
        
        this.capSolves = 0

        this.genData()
    }

    async controller(step) {
        try {
            const nextStep = await this[step]();
            setTimeout(() => {
                this.controller(nextStep);
            }, 3500);
        } catch (error) {
            try {
                if (error.msg == undefined) {
                    throw 'Task stopped'
                }

                this.status(error.msg, error.type || 'Error');
                setTimeout(() => {
                    this.controller(error.nextStep || step);
                }, error.timeout || 3500);
            } catch (e) {
                await this.stop()
            }
        }
    }

    start() {   
        this.status(`Loading config (${this.email} / ${this.proxy})`, 'Info')
        this.controller('getIp')
    }

    stop() {
        this.status(`Task stopped`, 'Warn');
    }

    getIp() {
        return new Promise((resolve, reject) => {
            this.status('Loading proxy', 'Status')
            request('https://api.ipify.org', {method: "GET", proxy: this.proxy}, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    this.ip = body
                    // Used for debugging the proxy in the webhook
                    
                    this.status(`IP Found: ${body}`, 'Info')

                    resolve('loadSite')
                }
            });
        })
    }

    loadSite() {
        return new Promise((resolve, reject) => {
            this.status('Loading site', 'Status')
            const opts = {
                method: "GET",
                jar: this.jar,
                proxy: this.proxy
            }
        
            request('https://signup.live.com/signup', opts, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    this.outlookData.redir = res.request.uri.href
                    
                    resolve('loadRedir')
                    //loadRedir()
                }
            })

        })
    }

    loadRedir() {
        return new Promise((resolve, reject) => {
            this.status('Loading redirect URL', 'Status')
            const opts = {
                method: "GET",
                jar: this.jar,
                proxy: this.proxy
            }
        
            request(this.outlookData.redir, opts, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    // TODO: Use html parser to clean this up

                    this.outlookData.uaid = this.outlookData.redir.split('uaid=')[1].split('&')[0]
                    let tcxt = body.split('"clientTelemetry":{"uaid":"')[1].split(',"tcxt":"')[1].split('"},')[0]
                    this.outlookData.tcxt = tcxt.replaceAll(`\\u002f`, "/").replaceAll(`\\u003a`, ":").replaceAll(`\\u0026`, "&").replaceAll(`\\u003d`, "=").replaceAll(`\\u002b`, "+")
        
                    let canary = body.split('"apiCanary":"')[1].split('"')[0]
                    this.outlookData.canary = canary.replaceAll(`\\u002f`, "/").replaceAll(`\\u003a`, ":").replaceAll(`\\u0026`, "&").replaceAll(`\\u003d`, "=").replaceAll(`\\u002b`, "+")
        
                    this.outlookData.randomNum = body.split(`var randomNum="`)[1].split(`"`)[0]
                    this.outlookData.key = body.split(`var Key="`)[1].split(`"`)[0]
        
                    this.outlookData.SKI = body.split(`var SKI="`)[1].split(`"`)[0]
                    resolve('main')
                }
            })
        })
    }

    main() {
        return new Promise((resolve, reject) => {
            if (this.outlookData.solved) {
                this.status('Submitting captcha and data', 'Status')
    
                this.outlookData.body = this.genSolvedBody()


                // TODO: add the stuff below to lower line count, instead of using independent function
                // as method of debugging

                
                // this.outlookData.body["HSol"] = this.outlookData.solve
                // this.outlookData.body["encAttemptToken"] = this.outlookData.encAttemptToken
                // this.outlookData.body["dfpRequestId"] = this.outlookData.dfpRequestId
                // this.outlookData.body["HPId"] = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
                // this.outlookData.body["HType"] = "enforcement"
                // this.outlookData.body["SuggestedAccountType"] = "EASI"
                // this.outlookData.body["SuggestionType"] = "Prefer"
                // this.outlookData.body["SiteId"] = "68692"
                //console.log(body);
            } else {
                this.status('Submitting data', 'Status')   
                
                this.outlookData.body = this.genBody()
            }

            
    
            const outlookheaders = {
                "accept": "application/json",
                "accept-encoding": "gzip, deflate, br",
                "accept-language": "en-US,en;q=0.9",
                "cache-control": "no-cache",
                "canary": this.outlookData.canary,
                "content-type": "application/json",
                "dnt": "1",
                "hpgid": "2006" + this.rNum(10,99).toString(),
                "origin": "https://signup.live.com",
                "pragma": "no-cache",
                "referer": this.outlookData.redir,
                "scid": "100118",
                "sec-ch-ua": `" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"`,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": `"Windows"`,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "tcxt": this.outlookData.tcxt,
                "uaid": this.outlookData.uaid,
                "uiflvr": "1001",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
                "x-ms-apitransport": "xhr",
                "x-ms-apiversion": "2"
            }

            const opts = {
                body: JSON.stringify(this.outlookData.body),
                headers: outlookheaders,
                method: "POST",
                jar: this.jar,
                proxy: this.proxy
            }
            
        
            request(`https://signup.live.com/API/CreateAccount?lic=1&uaid=${this.outlookData.uaid}`, opts, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    try {
                        let loginResp = JSON.parse(body).error
                        if (!loginResp || loginResp == undefined) {
                            this.status(`Success: (${this.email} : ${this.pw})`, 'Success')
                            resolve('sendWhook')
                        } else {
                            if (loginResp.code == "1042") {
                                // TODO: Add sms support
                                // rn redoing this step on timeout seems to bypass sms required, but 
                                // good idea to add support
                                reject({msg: "Flagged proxy, sms required", timeout: 10000})
                            } else if (loginResp.code == "1041") {
                                this.status(`FunCaptcha found`, 'Warn')
                                this.outlookData.encAttemptToken = loginResp.data.split(`encAttemptToken":"`)[1].split(`"`)[0].replaceAll(`\\u002f`, "/").replaceAll(`\\u003a`, ":").replaceAll(`\\u002b`, "+").replaceAll(`\\u0026`, "&").replaceAll(`\\u003d`, "="); 
                                this.outlookData.dfpRequestId = loginResp.data.split(`dfpRequestId":"`)[1].split(`"`)[0];
                                
                                
                                if (this.capSolves < this.captchaLimit) {
                                    this.capSolves += 1
                                    this.capUrl = this.gen2cap()
                                    this.outlookData.solved = false
                                    resolve('loadCaptcha')
                                } else {
                                    reject({msg: `Captcha limit`, nextStep: 'stop'})
                                }
                            } else if (loginResp.code == "1043") {
                                this.rotateProxy()
                                
                                this.outlookData.solved = false
                                this.jar = request.jar()
                                reject({msg: `Bad captcha submission, restarting session (${this.proxy})`, nextStep: "loadSite"})
                            } else {             
                                // TODO: add more error codes

                                // reject({msg: `Error code: ${loginResp.code}`})})                   
                                reject({msg: `Unforseen response: ${body}`, type: 'Info', nextStep: 'stop'})
                            }
                        }
                    } catch (e) {
                        console.log(body);
                        reject({msg: e})
                    }
                }
            })
        })
    }

    loadCaptcha() {
        return new Promise((resolve, reject) => {

            request(this.capUrl, {method: "GET"}, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    let resp = body.split('|')
    
                    if (resp[0] == "OK") {
                        this.capId = resp[1]
                        this.poll = 0
                        resolve('pollCap')
                    } else {
                        const message = "Error: " + resp[0]
                        
                        reject({msg: message, nextStep: 'stop'})
                    }
                }
            });
        });
    }

    pollCap() {
        return new Promise((resolve, reject) => {
            this.status(`Polling captcha [${this.poll}] / (${this.capSolves} Token(s) requested)`, "Warn")

            let url = `https://2captcha.com/res.php?key=${this.key}&action=get&id=${this.capId}`
  

            request(url, {method: "GET"}, (err, res, body) => {
                if (err) {
                    reject({msg: err})
                } else {
                    if (body == "CAPCHA_NOT_READY") {
                        this.poll += 1
                        resolve('pollCap')
                    } else {
                        if (body.split('|')[0] == "OK") {
                            this.outlookData.solved = true
                            this.outlookData.solve = body.replace("OK|","").replaceAll("&", "|").replace("meta=7|pk=", "meta=7|lang=en|pk=")
                            resolve('main')
                        } else if (body.split('|')[0] == "ERROR_CAPTCHA_UNSOLVABLE") {
                            this.poll = 0
                            
                            if (this.capSolves < 3) {
                                this.capSolves += 1
                                this.capUrl = this.gen2cap()
                                this.outlookData.solved = false
                                
                                reject({msg: "Bad captcha: ERROR_CAPTCHA_UNSOLVABLE", nextStep: 'loadCaptcha'})
                            } else {                                
                                reject({msg: `Captcha limit`, nextStep: 'stop'})
                            }
                        } else {
                            reject({msg: `Bad solve: ${body}`, nextStep: 'stop'})
                        }
                    }
                }
            })
        });
    }
    
    rNum(min, max) { // min and max included 
        return Math.floor(Math.random() * (max - min + 1) + min)
    }  

    randPw() {
        let pw = password.randomPassword({ characters: [password.lower, password.upper, password.digits] })
        pw = pw.slice(0, (pw.length-5))
        let num = this.rNum(1000,9999)
        pw = pw + "!" + num.toString() 
        pw += "Aa"
        return pw
    }

    genData() {
        let fname = random_name({ first: true })
        let lname = random_name({ last: true })
        let day = this.rNum(10, 25)
        let month = this.rNum(3, 9)
        let year = this.rNum(1969, 1999)
        this.birthday = `${day}:0${month}:${year}`

        this.outlookData = {fname: fname, lname: lname, day: day, month: month, year: year}
    }

    rotateProxy() {
        this.proxy = this.proxies[this.rNum(0, this.proxies.length - 1)]
    }

    sendWhook() {
        return new Promise((resolve, reject) => {
            try {
                const embed = new MessageBuilder()
                .setTitle('Outlook Account Generated Successfully')
                .addField('Email', `||${this.email}||`, true)
                .addField('Password', `||${this.pw}||`, true)
                .addField('Proxy', `||${this.ip}||`)
                .setTimestamp();
                this.webhook.send(embed);
                resolve('stop')
            } catch (e) {
                reject({msg: e, nextStep: 'stop'})
            }
        });
    }

    errorCodes() {
        // TODO: Add matching functionality for extra codes
        let codes = {
            "hipValidationError": "1043",
            "hipNeeded": "1040",
            "hipEnforcementNeeded": "1041",
            "hipSMSNeeded": "1042",
            "dailyLimitIDsReached": "450",
            "oneTimeCodeInvalid": "1304",
            "verificationSltInvalid": "1324",
            "membernameTaken": "1058",
            "domainNotAllowed": "1117",
            "domainIsReserved": "1181",
            "forbiddenWord": "403",
            "passwordIncorrect": "1002",
            "passwordConflict": "1009",
            "invalidEmailFormat": "1062",
            "invalidPhoneFormat": "1063",
            "invalidBirthDate": "1039",
            "invalidGender": "1243",
            "invalidFirstName": "1240",
            "invalidLastName": "1241",
            "maximumOTTDailyError": "1204",
            "bannedPassword": "1217",
            "proofAlreadyExistsError": "1246",
            "domainExistsInAad": "1184",
            "domainExistsInAadSupportedLogin": "1185",
            "membernameTakenEasi": "1242",
            "membernameTakenPhone": "1052",
            "signupBlocked": "1220",
            "invalidMemberNameFormat": "1064",
            "passwordRequired": "1330",
            "emailMustStartWithLetter": "1256",
            "evictionWarningRequired": "1334"
        }
    }

    genBody() {
        let ts = new Date();
        this.outlookData.cipher = genCipher("","","newpwd", this.pw, this.outlookData.randomNum, this.outlookData.key)
        
        let body = {
            "RequestTimeStamp": ts,
            "MemberName":`${this.email}@outlook.com`,
            "CheckAvailStateMap":[`${this.email}@outlook.com:undefined`],
            "EvictionWarningShown":[],"UpgradeFlowToken":{},
            "FirstName":this.outlookData.fname,
            "LastName":this.outlookData.lname,
            "MemberNameChangeCount":1,
            "MemberNameAvailableCount":1,
            "MemberNameUnavailableCount":0,
            "CipherValue": this.outlookData.cipher,
            "SKI":this.outlookData.SKI,
            "BirthDate": this.birthday,
            "Country":"US",
            "IsOptOutEmailDefault":false,
            "IsOptOutEmailShown":true,
            "IsOptOutEmail":true,
            "LW":true,
            "SiteId":"292841",
            "IsRDM":0,
            "WReply": null,
            "ReturnUrl":null,
            "SignupReturnUrl":null,
            "uiflvr":1001,
            "uaid":this.outlookData.uaid,
            "SuggestedAccountType":"OUTLOOK",
            "SuggestionType":"Locked",
            // TODO: Figure out HFId and significance
            //"HFId":"9a166ed80043424d883dafb778efec5d",
            "encAttemptToken":"",
            "dfpRequestId":"",
            "scid":100118,
            "hpgid":200650
        }
        
        return body
    }

    genSolvedBody() {
        let ts = new Date();
        this.outlookData.cipher = genCipher("","","newpwd", this.pw, this.outlookData.randomNum, this.outlookData.key)

        let body = {
            "RequestTimeStamp": ts,
            "MemberName":`${this.email}@outlook.com`,
            "CheckAvailStateMap":[
               `${this.email}@outlook.com:undefined`
            ],
            "EvictionWarningShown":[
               
            ],
            "UpgradeFlowToken":{
               
            },
            "FirstName":this.outlookData.fname,
            "LastName":this.outlookData.lname,
            "MemberNameChangeCount":1,
            "MemberNameAvailableCount":1,
            "MemberNameUnavailableCount":0,
            "CipherValue":this.outlookData.cipher,
            "SKI":this.outlookData.SKI,
            "BirthDate": this.birthday,
            "Country":"US",
            "IsOptOutEmailDefault":false,
            "IsOptOutEmailShown":true,
            "IsOptOutEmail":true,
            "LW":true,
            "SiteId":"68692",
            "IsRDM":0,
            "WReply":null,
            "ReturnUrl":null,
            "SignupReturnUrl":null,
            "uiflvr":1001,
            "uaid": this.outlookData.uaid,
            "SuggestedAccountType":"EASI",
            "SuggestionType":"Prefer",
            // TODO: Figure out HFId and significance
            //"HFId":"405de830c1434978bfe8f047e6dca9dc",
            "HType":"enforcement",
            "HSol":this.outlookData.solve,
            "HPId":"B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
            "encAttemptToken": this.outlookData.encAttemptToken,
            "dfpRequestId":this.outlookData.dfpRequestId,
            "scid":100118,
            "hpgid":201040
        }
        // 75561a25d05247be7.4193130101|r=us-east-1|metabgclr=%23ffffff|maintxtclr=%231B1B1B|mainbgclr=%23ffffff|guitextcolor=%23747474|metaiconclr=%23757575|meta_height=325|meta=7|lang=en|pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA|at=40|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-us-east-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com
        // 99861a26197e42154.0037844305|r=eu-west-1|metabgclr=%23ffffff|maintxtclr=%231B1B1B|mainbgclr=%23ffffff|guitextcolor=%23747474|metaiconclr=%23757575|meta_height=325|meta=7|pk=B7D8911C-5CC8-A9A3-35B0-554ACEE604DA|at=40|ht=1|ag=101|cdn_url=https%3A%2F%2Fclient-api.arkoselabs.com%2Fcdn%2Ffc|lurl=https%3A%2F%2Faudio-eu-west-1.arkoselabs.com|surl=https%3A%2F%2Fclient-api.arkoselabs.com
        return body
    }

    gen2cap() {
        let pubkey = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
        let pageurl = "https://signup.live.com/signup?lic=1&uaid=" + this.outlookData.uaid
    
        return `https://2captcha.com/in.php?key=${this.key}&method=funcaptcha&publickey=${pubkey}&surl=https://client-api.arkoselabs.com&pageurl=${pageurl}`
    }   

    status(msg, type) {
        let color = 'red'
        switch (type.toLowerCase()) {
            case 'status':
                color = 'magenta'
                break
            case 'error':
                color = 'red'
                break
            case 'success':
                color = 'green'
                break
            case 'warn':
                color = 'blue'
                break
            case 'info':
                color = 'yellow'
                break
            default:
                color = 'grey'
                break
        }

        console.log(`| Id: ${this.id} | ${type} | Message: ${msg} |`[color]);
    }
}


module.exports = Outlook;