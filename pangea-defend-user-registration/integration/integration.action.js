
exports.onExecutePreUserRegistration = async (event, api) => {
	  const Pangea = require('node-pangea');
	  const domain = "aws.us.pangea.cloud";
	  const token = event.secrets.token;
	  const configId = event.configuration.configId;
	  const config = new Pangea.PangeaConfig({ domain: domain, configId: configId });
	  const audit = new Pangea.AuditService(token, config);
	  const embargo = new Pangea.EmbargoService(token, config);
	  const domainIntel = new Pangea.DomainIntelService(token, config);

	  const ip = event.request.ip;
	  const check_domain = event.user.email.split("@")[1];
	  const options = { provider: "domaintools", verbose: true, raw: true };
	  
	  let context = {
		      "connection":event.connection,
		      "request":event.request,
		      "user":event.user
		      };
	  let data = {
		      "actor": event.user.email,
		      "action": "New Account Registration Defense",
		      "target": event.request.hostname,
		      "new": context,
		      "source": check_domain,
		      "message": ""
		      };

	  var embargo_response;
	  var domain_response;

	  try{
		      //console.log("Checking Embargo IP : '%s'", ip);
		      domain_response = await domainIntel.lookup(check_domain, options);
		      data.new['domain_response'] = domain_response.gotResponse.body;
		      //console.log("Response: ", ebmargo_response.gotResponse.body);
		    } catch(error){
			        domain_response = {"status":"Failed", "summary":error};
			      };

	  try{
		      //console.log("Checking Embargo IP : '%s'", ip);
		      embargo_response = await embargo.ipCheck(ip);
		      data.new['embargo_response'] = embargo_response.gotResponse.body;
		      //console.log("Response: ", ebmargo_response.gotResponse.body);
		    } catch(error){
			        embargo_response = {"status":"Failed", "summary":error};
			      };
	  
	  
	  if (embargo_response.status == "Success" && embargo_response.result.count == 0){
		      data["status"] = "Success";
		      data["message"] += " Passed Embargo Check,";
		    };
	  if (domain_response.status == "Success" && domain_response.result.raw_data.response.risk_score < 70){
		      data["status"] = "Success";
		      data["message"] += " Passed Domain Check,";
		    };
	  if (embargo_response.result.count > 0 ||  embargo_response.status != "Success" || domain_response.status != "Success" || domain_response.result.raw_data.response.risk_score > 70){
		      const LOCALIZED_MESSAGES = {
			            en: 'You are not allowed to register.',
			            es: 'No tienes permitido registrarte.'
			          };

		      const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
		      api.access.deny('no_signups_from_failed_check', userMessage);
		      data["status"] = "Failed";
		      if (embargo_response.result.count > 0 ||  embargo_response.status != "Success"){
			              data["message"] += " Failed Embargo Check - " + embargo_response.summary + ",";
			          };
		      if (domain_response.result.raw_data.response.risk_score > 70){
			            domain_response.summary = "Domain was determined to be suspicious with a score of " + domain_response.result.raw_data.response.risk_score;
			            data["message"] += " Failed Domain Check - " + domain_response.summary + ",";
			          }
		      else if (domain_response.status != "Success"){
			            data["message"] += " Failed Domain Check - " + domain_response.summary + ",";
			          };
		    };
	 
	  const logResponse = await audit.log(data);
};
