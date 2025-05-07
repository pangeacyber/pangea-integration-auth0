exports.onExecutePostLogin = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event?.configuration?.DOMAIN ? event?.configuration?.DOMAIN : event?.secrets?.DOMAIN;
    const config = new Pangea.PangeaConfig({domain: domain});
    const embargo = new Pangea.EmbargoService(token, config);

    const ip = event.request.ip;

    let context = {
        "connection": event.connection,
        "request": event.request,
        "user": event.user
    };
    let data = {
        "actor": event.user.email,
        "action": "Embargo Check IP",
        "target": event.request.hostname,
        "new": context,
        "source": ip
    };

    let embargo_response;
    
    try {
        embargo_response = await embargo.ipCheck(ip);

        data.new['embargo_response'] = embargo_response.gotResponse.body;
    } catch (error) {
        embargo_response = {"status": "Failed", "summary": error};
    }

    /**
     * Embargo 'success' means it was able to return information, it doesn't mean the IP is blocked or not
     * 
     * If we have a result object and success we should check it does not have any embargoed items (which is why we don't only check for 'success')
     * If we do _not_ have a result object and success, we assume we could not find info for the specified input and so we will continue the new account flow
     */
    if (embargo_response.status == "Success" && ((embargo_response?.result && embargo_response?.result?.count == 0) || (embargo_response?.result === null || Object.keys(embargo_response.result).length === 0))) {
        data["status"] = "Success";
        data["message"] = "Passed Embargo Check";
    } else {
        api.access.deny('embargo_check_failed', "Login Failed");
        data["status"] = "Failed";
        data["message"] = "Failed Embargo Check - " + embargo_response.summary;
    }
};
