const Outlook = require('./outlook')
const fs = require('fs')

fs.readFile('./proxies.txt', 'utf8', (err, data) => {
    const rawProxies = []
    if (err) {
        console.log("Error reading proxies");
        process.exit()
    } else {
        data.split('\n').forEach(proxy => {
            rawProxies.push(proxy.trim())
        });
    }

    let capKey = ""
    let webhook = ""
    let taskCount = 1
    let captchaLimit = 3

    for (let i = 0; i < taskCount; i++) {
        try {
            const outlook = new Outlook({id: i, key: capKey, webhook: webhook, limit: captchaLimit, proxyList: rawProxies})
            outlook.start()
        } catch (e) {
            console.log(e);
        }
    }
});
