exports.onExecutePostLogin = async (event, api) => {
    const Pangea = require('pangea-node-sdk');
    const token = event.secrets.TOKEN;
    const domain = event?.configuration?.DOMAIN ? event.configuration.DOMAIN : event?.secrets?.DOMAIN;
    const config = new Pangea.PangeaConfig({domain: domain});
    // const audit = new Pangea.AuditService(token, config);
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

    if (embargo_response.status == "Success" && embargo_response.result.count == 0) {
        data["status"] = "Success";
        data["message"] = "Passed Embargo Check";
    } else {
        api.access.deny('embargo_check_failed', "Login Failed");
        data["status"] = "Failed";
        data["message"] = "Failed Embargo Check - " + embargo_response.summary;
    }
    
    // audit.log(data);
};
