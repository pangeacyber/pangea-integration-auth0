exports.onExecutePostLogin = async (event, api) => {
	  const Pangea = require('node-pangea');
	  const domain = "aws.us.pangea.cloud";
	  const token = event.secrets.TOKEN;
	  const configId = event.configuration.CONFIGID;
	  const config = new Pangea.PangeaConfig({ domain: domain, configId: configId });
	  const audit = new Pangea.AuditService(token, config);
	  const domainIntel = new Pangea.DomainIntelService(token, config);
	  
	  const check_domain = event.user.email.split("@")[1];
	  const options = { provider: "domaintools", verbose: true, raw: true };
	  let context = {
		      "connection":event.connection,
		      "request":event.request,
		      "user":event.user
		      };
	  let data = {
		      "actor": event.user.email,
		      "action": "Domain Check",
		      "target": event.request.hostname,
		      "new": context,
		      "source": check_domain
		      };
	  
	  var domain_response;
	  try{
		      //console.log("Checking Embargo IP : '%s'", ip);
		      domain_response = await domainIntel.lookup(check_domain, options);
		      data.new['domain_response'] = domain_response.gotResponse.body;
		      //console.log("Response: ", ebmargo_response.gotResponse.body);
		    } catch(error){
			        domain_response = {"status":"Failed", "summary":error};
			      };
	  
	  if (domain_response.status == "Success" && domain_response.result.raw_data.response.risk_score < 70){
		      data["status"] = "Success";
		      data["message"] = "Passed Domain Check";
		    }
	  else{
		      // localize the error message 
		      const LOCALIZED_MESSAGES = {
			            en: 'Domain Check Failed.',
			            es: 'No tienes permitido registrarte.'
			          };
		      if (domain_response.status == "Success" && domain_response.result.raw_data.response.risk_score > 70){
			            domain_response.summary = "Domain was determined to be suspicious with a score of " + domain_response.result.raw_data.response.risk_score;
			          }
		      const userMessage = LOCALIZED_MESSAGES[event.request.language] || LOCALIZED_MESSAGES['en'];
		      api.access.deny('domain_check_failed', userMessage);
		      data["status"] = "Failed";
		      data["message"] = "Failed Domain Check - " + domain_response.summary;
		    };
	  //console.log("Data: ", data);
	  //const logResponse = await audit.log(data);
	  //console.log("Data: ", logResponse)
	};
