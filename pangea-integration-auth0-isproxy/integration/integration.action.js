exports.onExecutePostLogin = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event?.configuration?.DOMAIN ? event.configuration.DOMAIN : event?.secrets?.DOMAIN;
    const intelprovider = event?.configuration?.PROVIDER ? event.configuration.PROVIDER : event?.secrets?.PROVIDER;
    const config = new Pangea.PangeaConfig({domain: domain});
    const audit = new Pangea.AuditService(token, config);
    const ipIntel = new Pangea.IPIntelService(token, config);

    const ipv4Test = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/


    const ip = event.request.ip;
    const options = {provider: intelprovider, verbose: true, raw: true};

    let context = {
        "connection": event.connection,
        "request": event.request,
        "user": event.user
    };
    let data = {
        "actor": event.user.email,
        "action": "Proxy Check",
        "target": event.request.hostname,
        "new": context,
        "source": ip
    };

    if (ipv4Test.test(ip)) {
        let ip_response;

        try {
            ip_response = await ipIntel.isProxy(ip, options);

            data.new['ip_response'] = ip_response.gotResponse.body;
        } catch (error) {
            ip_response = {"status": "Failed", "summary": error};
        }

        if (ip_response.status == "Success" && ip_response.result.data.is_proxy === false) {
            data["status"] = "Success";
            data["message"] = "Passed Proxy Check";
        } else {
            api.access.deny('proxy_check_failed', "Login Failed");
            data["status"] = "Failed";
            data["message"] = "Failed Proxy Check - " + ip_response.summary;
        }
    } else {
        data["status"] = "Success";
        data["message"] = "Skipped proxy check, IP not valid IPv4";
    }

    await audit.log(data);
};
