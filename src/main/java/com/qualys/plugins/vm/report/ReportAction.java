package com.qualys.plugins.vm.report;

import java.io.File;
import java.io.StringReader;
import java.util.logging.Logger;

import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.bind.JavaScriptMethod;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.client.QualysVMResponse;
import com.qualys.plugins.vm.util.Helper;

import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;
import hudson.util.Secret;
import net.sf.json.JSONObject;

@Extension
public class ReportAction implements Action {
    private String scanId;
    private String scanRef;
    private String status;
    private String subScanStatus;
    private String scanName;
    private String portalUrl; 
    private String duration;
    private String reference; 
    private String scanType;
    private String scanTarget;
    private String reportUrl;
    private String apiServer;
    private String apiUser;
    private Secret apiPass;
    private boolean useProxy;
    private String proxyServer;
    private int proxyPort;
    private String proxyUsername;
    private Secret proxyPassword;    
    private JSONObject scanResult;
    
    private Run<?, ?> run;
	private String scannerName;
    
    private final static Logger logger = Helper.getLogger(ReportAction.class.getName());

    public ReportAction() { }

    public ReportAction(Run<?, ?> run, String scanRef, String scanId, String scanTarget, String scannerName,
    		String scanName, String apiServer, String apiUser, Secret apiPass, boolean useProxy, 
    		String proxyServer, int proxyPort, String proxyUsername, Secret proxyPassword, String serverPlatformUrl,
    		String duration, String reference, String scanType, String scanStatus, String subScanStatus) {
        this.scanId = scanId;
        this.scanRef = scanRef;
        this.scanName = scanName;
        this.scannerName = scannerName;
        this.apiServer = apiServer;
        this.apiUser = apiUser;
        this.apiPass = apiPass;
        this.useProxy = useProxy;
        this.proxyServer = proxyServer;
        this.proxyPort = proxyPort;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = proxyPassword;
        this.portalUrl = serverPlatformUrl;
        this.status = scanStatus;
        this.subScanStatus = subScanStatus;
        this.duration = duration;
        this.scanTarget = scanTarget;
        this.reference = reference;
        this.scanType = scanType;
        this.reportUrl = (portalUrl.endsWith("/")? portalUrl : portalUrl + "/") + "fo/report/report_view.php?&id=" + scanId;        
        this.run = run;
    }
    
    public String getScanId() {
    	return this.scanId;
    }
        
    public String getScanTarget() {
    	return this.scanTarget;
    }
    
    public String getScanName() {
    	return this.scanName;
    }
    
    public String getReportUrl() {
    	return this.reportUrl;
    }

    public String getScanRef() {
    	return this.scanRef;
    }
    
    public String getBuildStatus() {
    	JsonObject respObj = null;
    	
    	try {    		
    		String scanIdNew = scanRef.replace("/","_"); 
    		String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_" + scanIdNew + ".json";    		
        	File f = new File(filename);
        	Gson gson = new Gson();
        	if(f.exists()){
        		String resultStr = FileUtils.readFileToString(f);
        		String resultStrClean = resultStr;
        		JsonReader jr = new JsonReader(new StringReader(resultStrClean.trim())); 
        		jr.setLenient(true); 
        		respObj = gson.fromJson(jr, JsonObject.class);        		
        	}
        	//if failOnconditions configured then only we will have evalResult
        	if(respObj != null && (respObj.has("evaluationResult") && !respObj.get("evaluationResult").isJsonNull())){
        		
        		JsonElement respEl = respObj.get("evaluationResult");
       			JsonObject evalresult = respEl.getAsJsonObject();
       	
       			if (evalresult.get("evaluationStatus") == null){
       				//compute the evaluation status based on other keys
       				if (evalresult.size() == 0 ) {
       					return "Not Found";
       				}
       				boolean status = true, criteriaNotConfigured = true;
       				if (evalresult.has("qids") && !evalresult.get("qids").isJsonNull()) {
       					if (evalresult.get("qids").getAsJsonObject().get("result") != null) {
       						status = evalresult.get("qids").getAsJsonObject().get("result").getAsBoolean();
       						criteriaNotConfigured = false;
           					if (!status) {
               					return "FAILED";
               				}
       					}
       					
       				}	
       				
       				if (evalresult.has("severities") && !evalresult.get("severities").isJsonNull()) {
       					JsonElement sev = evalresult.get("severities");
       					criteriaNotConfigured = false;
       	       			JsonObject sevObject = sev.getAsJsonObject();
       	       			for (int i = 1; i <= 5; ++i ) {
       	       				status = true;
       	       				String sevNumber = String.valueOf(i);
	       	       			if (sevObject.has(sevNumber) && !sevObject.get(sevNumber).isJsonNull()) {
		       					status = sevObject.get(sevNumber).getAsJsonObject().get("result").getAsBoolean();
		       				}
		       	       		if (!status) {
		       					return "FAILED";
		       				}
       	       			}
       				}
       				
       				if (evalresult.has("cveIds") && !evalresult.get("cveIds").isJsonNull()) {
       					if (evalresult.get("cveIds").getAsJsonObject().get("result") != null) {
       						status = evalresult.get("cveIds").getAsJsonObject().get("result").getAsBoolean();
       						criteriaNotConfigured = false;
           					if (!status) {
               					return "FAILED";
               				}
       					}	
       				}	
       				
       				if (evalresult.has("cvss_base") && !evalresult.get("cvss_base").isJsonNull()) {
       					status = evalresult.get("cvss_base").getAsJsonObject().get("result").getAsBoolean();
       					criteriaNotConfigured = false;
       					if (!status) {
           					return "FAILED";
           				}
       				}	
       				
       				if (evalresult.has("cvss3_base") && !evalresult.get("cvss3_base").isJsonNull()) {
       					status = evalresult.get("cvss3_base").getAsJsonObject().get("result").getAsBoolean();
       					criteriaNotConfigured = false;
       					if (!status) {
           					return "FAILED";
           				}
       				}	
       				
       				if (evalresult.has("pci_vuln") && !evalresult.get("pci_vuln").isJsonNull()) {
       					status = evalresult.get("pci_vuln").getAsJsonObject().get("result").getAsBoolean();
       					criteriaNotConfigured = false;
       					if (!status) {
           					return "FAILED";
           				}
       				}
       				
       				if (criteriaNotConfigured) {
       					return "Criteria not configured";
       				}
       				
       				return "PASSED";
       				
       			}
       			
       			if(evalresult.get("evaluationStatus").isJsonNull()) {
       				return "Criteria not configured";
       			}
       			
       			String status = evalresult.get("evaluationStatus").getAsString();
       			
       			if (status.equals("pass")) {
       				return "PASSED";
       			} else if(status.equals("fail")){
       				return "FAILED";
       			} 
       		
        	}else {
        		return "Not Found";
        	}  
    	}catch(Exception e) {
    		logger.info("Error parsing evaluationResult from scan Result: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement);
    	}
    	return "-";
    }
    
    @JavaScriptMethod
    public JSONObject getScanResults() {
    	this.scanResult = new JSONObject();
    	JsonObject respObj = null;
    	QualysVMResponse response = null;
    	JSONObject confirmObj = new JSONObject();
		JSONObject potentialObj = new JSONObject();
		int qids = 0, igs = 0, cVuln = 0, pVuln = 0;
    	try {    		
    		String scanIdNew = scanRef.replace("/","_");    		
    		String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_" + scanIdNew + ".json";    		
        	File f = new File(filename);
        	Gson gson = new Gson();
        	if(f.exists()){
        		String resultStr = FileUtils.readFileToString(f);
        		String resultStrClean = resultStr;
        		JsonReader jr = new JsonReader(new StringReader(resultStrClean.trim())); 
        		jr.setLenient(true); 
        		respObj = gson.fromJson(jr, JsonObject.class);        		
        	}else if (this.status.equalsIgnoreCase("Finished")){
        		try {
        			QualysAuth auth = new QualysAuth();
        	    	auth.setQualysCredentials(this.apiServer, this.apiUser, this.apiPass.getPlainText());
        	    	if(useProxy) {
        	        	//int proxyPortInt = Integer.parseInt(proxyPort);
        	        	auth.setProxyCredentials(this.proxyServer, this.proxyPort, this.proxyUsername, this.proxyPassword.getPlainText(), this.useProxy);
        	    	}
        	    	QualysVMClient qualysClient = new QualysVMClient(auth, System.out);
	            	response = qualysClient.getScanResult(scanRef);
        		}catch(Exception e) {
        			for (StackTraceElement traceElement : e.getStackTrace())
                        logger.info("\tat " + traceElement);
        			throw new Exception(e);
        		}   
        		respObj = response.getResponse();
        	}
        	//if failOnconditions configured then only we will have evalResult
        	if(respObj != null && (respObj.has("evaluationResult") && !respObj.get("evaluationResult").isJsonNull())){
        		scanResult.put("isEvaluationResult", 1);
        		JsonElement respEl = respObj.get("evaluationResult");
       			JsonObject evalresult = respEl.getAsJsonObject();
       			
       			GsonBuilder builder = new GsonBuilder();
    			Gson gsonObject = builder.serializeNulls().create(); // for null values
    			
    			String sevVulnsJson = gsonObject.toJson(evalresult);
    			JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);
    			
       			scanResult.put("evaluationResult", JSONObject.fromObject(gsonObject.toJson(sevVulnsElement)));
        	}else {
        		scanResult.put("isEvaluationResult", 0);
        		scanResult.put("evaluationResult", JSONObject.fromObject("{}"));
        	}
        	
   			if(respObj == null || !respObj.has("data")) {
   				for(int i=1 ; i<=5 ; i++) {
   					confirmObj.put(Integer.toString(i), cVuln);
   					potentialObj.put(Integer.toString(i), pVuln);   					
   				}
   				scanResult.put("qidsCount", 0);
   				scanResult.put("igsCount", 0);
   				scanResult.put("cVulnCount", cVuln);   				
   				scanResult.put("pVulnCount", pVuln);   				
   				scanResult.put("cVulnsBySev", confirmObj);
   				scanResult.put("pVulnsBySev", potentialObj);
   			//Vuln table   				
				scanResult.put("vulnsTable", JSONObject.fromObject(gson.toJson(Helper.removeBigData(respObj))));				
   			}else {
   				JsonArray dataArr = respObj.get("data").getAsJsonArray();
   				JsonObject scanObj = dataArr.get(1).getAsJsonObject();
   				
   				// Result Summary 
   				
   				String[] summaryAttrs = {"launch_date", "type", "status", "duration", "network"};
   				for(int i = 0; i<summaryAttrs.length; i++) {
					try {
						scanResult.put(summaryAttrs[i], scanObj.get(summaryAttrs[i]).getAsString());
					}
					catch(NullPointerException exc){
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], " - ");
					}
					catch(Exception exc) {
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], "Exception: " + exc.getMessage());
					}
				}
   				// Result stats 
   				int confirmedVulns [] = new int[6];
				int potentialVulns [] = new int[6];
   				for (JsonElement s: dataArr) {
   					JsonObject scanObject = s.getAsJsonObject();
   					if(scanObject.has("qid") && scanObject.has("type")) {
   						qids++;
   						if (scanObject.get("type").getAsString().equalsIgnoreCase("Ig") ) {	   						
	   						igs++;
   						}	
   						if (scanObject.get("type").getAsString().equalsIgnoreCase("Vuln")) {
   							cVuln++;
   							if (scanObject.has("severity")) {
	   							int i = scanObject.get("severity").getAsInt();
	   							confirmedVulns[i]++;
   							}   						
   						} else if (scanObject.get("type").getAsString().equalsIgnoreCase("Practice")) {
   							pVuln++;   							
   							if (scanObject.has("severity")) {
   								int i = scanObject.get("severity").getAsInt();   							
   								potentialVulns[i]++;
   							}
   						}
   					}   						   			
   				}// end of for loop
   				for(int i=1 ; i<=5 ; i++) {
   					confirmObj.put(Integer.toString(i), confirmedVulns[i]);
   					potentialObj.put(Integer.toString(i), potentialVulns[i]);   					
   				}
   				scanResult.put("qidsCount", qids);
   				scanResult.put("igsCount", igs);
   				scanResult.put("cVulnCount", cVuln);   				
   				scanResult.put("pVulnCount", pVuln);   				
   				scanResult.put("cVulnsBySev", confirmObj);
   				scanResult.put("pVulnsBySev", potentialObj);   				
   				
   			//Vuln table   				
				scanResult.put("vulnsTable", JSONObject.fromObject(gson.toJson(Helper.removeBigData(respObj))));
   			}// end of else
    	}catch(Exception e) {    		
    		logger.info("Error parsing scan Result: " + e.getMessage());
    		scanResult.put("error", e.getMessage());    		
    	}    	
    	return scanResult;
    }
    

	@Override
	public String getIconFileName() {
		return "clipboard.png";
	}

	@Override
	public String getDisplayName() {
		return "Qualys Report for " + this.scanTarget;
	}

	@Override
	public String getUrlName() {		
		return "qualys_vm_scan_report_"+this.scanTarget+".html";
	}
}