exports.onExecutePreUserRegistration = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event?.configuration?.DOMAIN ? event.configuration.DOMAIN : event?.secrets?.DOMAIN;
    
    const domainintelprovider = event?.configuration?.DOMAIN_PROVIDER ? event.configuration.DOMAIN_PROVIDER : event?.secrets?.DOMAIN_PROVIDER;
    const ipintelprovider = event?.configuration?.IP_PROVIDER ? event.configuration.IP_PROVIDER : event?.secrets?.IP_PROVIDER;

    const config = new Pangea.PangeaConfig({domain: domain});
    const ipIntel = new Pangea.IPIntelService(token, config);
    const embargo = new Pangea.EmbargoService(token, config);
    const domainIntel = new Pangea.DomainIntelService(token, config);

    const ip = event.request.ip;
    const check_domain = event.user.email.split("@")[1];
    const domainoptions = {provider: domainintelprovider, verbose: true, raw: true};
    const ipoptions = {provider: ipintelprovider, verbose: true, raw: true};

    let context = {
        "connection": event.connection,
        "request": event.request,
        "user": event.user
    };
    let data = {
        "actor": event.user.email,
        "action": "New Account Registration Defense",
        "target": event.request.hostname,
        "new": context,
        "source": check_domain,
        "status": "Success",
        "message": ""
    };

    let embargo_response;
    let domain_response;
    let ip_response;

    try {
        embargo_response = await embargo.ipCheck(ip);
        data.new['embargo_response'] = embargo_response.gotResponse.body;
    } catch (error) {
        embargo_response = {"status": "Failed", "summary": error};
    }

    try {
        domain_response = await domainIntel.reputation(check_domain, domainoptions);
        data.new['domain_response'] = domain_response.gotResponse.body;
    } catch (error) {
        domain_response = {"status": "Failed", "summary": error};
    }
    try {
        ip_response = await ipIntel.reputation(ip, ipoptions);
        data.new['ip_response'] = ip_response.gotResponse.body;
    } catch (error) {
        ip_response = {"status": "Failed", "summary": error};
    }

    /**
     * Embargo 'success' means it was able to return information, it doesn't mean the IP is blocked or not
     * 
     * If we have a result object and success we should check it does not have any embargoed items (which is why we don't only check for 'success')
     * If we do _not_ have a result object and success, we assume we could not find info for the specified input and so we will continue the new account flow
     */
    if (embargo_response.status == "Success" && ((embargo_response?.result && embargo_response?.result?.count == 0) || (embargo_response?.result === null || Object.keys(embargo_response.result).length === 0))) {
        data["message"] += "Passed Embargo Check";
    } else {
        data["message"] += "Failed Embargo Check - " + embargo_response.summary;
        data["status"] = "Failed";
    }

    if (domain_response.status == "Success" && domain_response.result.data.score < 70) {
        data["message"] += "Passed Domain Check";
    } else {
        domain_response.summary = "Domain was determined to be suspicious with a score of " + domain_response.result.data.score;
        data["message"] += "Failed Domain Check - " + domain_response.summary;
        data["status"] = "Failed";
    }
    
    if (ip_response.status == "Success" && ip_response.result.data.score < 70) {
        data["message"] += "Passed IP Rep Check";
    } else {
        data["message"] += "Failed IP Rep Check - " + ip_response.summary;
        data["status"] = "Failed";
    }

    if (data["status"] == "Failed") {
        api.access.deny('domain_check_failed', "Registration Failed");
    }
};
