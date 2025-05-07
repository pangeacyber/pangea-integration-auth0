exports.onExecutePreUserRegistration = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event?.configuration?.DOMAIN ? event.configuration.DOMAIN : event?.secrets?.DOMAIN;
    const intelprovider = event?.configuration?.PROVIDER ? event.configuration.PROVIDER : event?.secrets?.PROVIDER;
    
    const config = new Pangea.PangeaConfig({domain: domain});
    const domainIntel = new Pangea.DomainIntelService(token, config);

    const check_domain = event.user.email.split("@")[1];
    const options = {provider: intelprovider, verbose: true, raw: true};

    let context = {
        "connection": event.connection,
        "request": event.request,
        "user": event.user
    };
    let data = {
        "actor": event.user.email,
        "action": "Domain Reputation",
        "target": event.request.hostname,
        "new": context,
        "source": check_domain
    };

    let domain_response;
    try {
        domain_response = await domainIntel.reputation(check_domain, options);
        data.new['domain_response'] = domain_response.gotResponse.body;
    } catch (error) {
        domain_response = {"status": "Failed", "summary": error};
    }

    if (domain_response.status == "Success" && domain_response.result.data.score < 70) {
        data["status"] = "Success";
        data["message"] = "Passed Domain Check";
    } else {

        if (domain_response.status == "Success" && domain_response.result.data.score > 70) {
            domain_response.summary = "Domain was determined to be suspicious with a score of " + domain_response.result.data.score;
        }
        api.access.deny('domain_check_failed', "Registration Failed");
        data["status"] = "Failed";
        data["message"] = "Failed Domain Check - " + domain_response.summary;
    }
};
