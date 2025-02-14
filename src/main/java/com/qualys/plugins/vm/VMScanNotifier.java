/* This file is responsible for the configuration in freestyle setup*/
/* BuildSteps that run after the build is completed. 
Notifier is a kind of Publisher that sends out the outcome of the builds to other systems and humans. 
This marking ensures that notifiers are run after the build result is set to its final value by other Recorders. 
To run even after the build is marked as complete, override needsToRunAfterFinalized to return true. */

package com.qualys.plugins.vm;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.qualys.plugins.vm.auth.QualysAuth;
import com.qualys.plugins.vm.client.QualysVMClient;
import com.qualys.plugins.vm.util.Helper;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

@Extension
public class VMScanNotifier extends Notifier implements SimpleBuildStep {
/* Variable Declaration */
	
	private String apiServer;
	private String platform;
    private String credsId;
    private String hostIp;
    private String ec2Id;
    private String ec2ConnDetails;
    private String ec2ConnName;
    private String ec2ConnAccountId;
    private String ec2ConnId;
    private String scanName;
    private String scannerName;
    private String optionProfile;
    private String network;
    private String proxyServer;
    private int proxyPort;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    private boolean useHost = false;
    private boolean useEc2 = false;
    private boolean runConnector = false;
    private String pluginName = "Qualys Host Scanning Connector";    
    private String pollingInterval;
    private String vulnsTimeout;    
    private int bySev;
    private boolean failBySev = false;    
    private String qidList;
    private boolean failByQids = false;    
    private String cveList;
    private boolean failByCves = false;    
    private String byCvss;
    private String cvssBase;
    private boolean failByCvss = false;    
    private String excludeList;
    private String excludeBy;
    private boolean doExclude;    
    private boolean evaluatePotentialVulns = false;
    private boolean failByPci = false;
    private String webhookUrl;    
    private final static String SCAN_NAME = "[job_name]_jenkins_build_[build_number]";
	private final static int PROXY_PORT = 80;
    private final static Logger logger = Helper.getLogger(VMScanNotifier.class.getName());
    private static final String xml10pattern = "[^"
            + "\u0009\r\n"
            + "\u0020-\uD7FF"
            + "\uE000-\uFFFD"
            + "\ud800\udc00-\udbff\udfff"
            + "]";
    
    private String hostIpValue;
	private String ec2IdValue;
    /* End of Variable Declaration */
    
    /*Getter Setters*/
    
    public VMScanNotifier() { }
    
    /*Getter Setters*/
    
    public String getPlatform() {
        return platform;
    }
    
    @DataBoundSetter
    public void setPlatform(String platform) {
        this.platform = platform;
    }
    
    public String getPollingInterval() {return pollingInterval;}
    @DataBoundSetter
	public void setPollingInterval(String pollingInterval) {this.pollingInterval = pollingInterval;}

	public String getVulnsTimeout() {return vulnsTimeout;}
	@DataBoundSetter
	public void setVulnsTimeout(String vulnsTimeout) {this.vulnsTimeout = vulnsTimeout;}

	public String getApiServer() {return apiServer;}	
	@DataBoundSetter
    public void setApiServer(String apiServer) {
		if (apiServer!=null && apiServer.endsWith("/")) {
			apiServer = apiServer.substring(0, apiServer.length() - 1);
		}
		this.apiServer = apiServer;
    }
	
	public boolean getFailByQids() {return failByQids;}
	@DataBoundSetter
	public void setFailByQids(boolean failByQids) {this.failByQids = failByQids;}
	
	public boolean getFailByCves() {return failByCves;}
	@DataBoundSetter
	public void setFailByCves(boolean failByCves) {this.failByCves = failByCves;}
	
	public boolean getFailByCvss() {return failByCvss;}
	@DataBoundSetter
	public void setFailByCvss(boolean failByCvss) {this.failByCvss = failByCvss;}
	
	public String getByCvss() {return byCvss;}
	@DataBoundSetter
	public void setByCvss(String byCvss) {this.byCvss = byCvss;}
	
	public String getCvssBase() {return cvssBase;}
	@DataBoundSetter
	public void setCvssBase(String cvssBase) {this.cvssBase = cvssBase;}

	public String getQidList() {return qidList;}
	@DataBoundSetter
	public void setQidList(String qidList) {this.qidList = qidList;}
	
	public String getCveList() {return cveList;}
	@DataBoundSetter
	public void setCveList(String cveList) {this.cveList = cveList;}
	
	public int getBySev() {return this.bySev;}
	@DataBoundSetter
	public void setBySev(int bySev) {this.bySev = bySev;}
		
	public boolean getFailBySev() {return failBySev;}
	@DataBoundSetter
	public void setFailBySev(boolean failBySev) {this.failBySev = failBySev;}

	public String getCredsId() {return credsId;}
	@DataBoundSetter
	public void setCredsId(String cred) {this.credsId = cred;}

    public String getHostIp() {return hostIp;}
    @DataBoundSetter
	public void setHostIp(String hostIp) {this.hostIp = hostIp;}
    
    public String getEc2Id() {return ec2Id;}    
    @DataBoundSetter
    public void setEc2Id(String ec2Id) {this.ec2Id = ec2Id;}
    
    public String getEc2ConnDetails() {return ec2ConnDetails;}    
    @DataBoundSetter
    public void setEc2ConnDetails(String ec2ConnDetails) {this.ec2ConnDetails = ec2ConnDetails;}
    
    public String getEc2ConnName() {return ec2ConnName;}    
    @DataBoundSetter
    public void setEc2ConnName(String ec2ConnName) {this.ec2ConnName = ec2ConnName;}
    
    public String getEc2ConnAccountId() {return ec2ConnAccountId;}    
    @DataBoundSetter
    public void setEc2ConnAccountId(String ec2ConnAccountId) {this.ec2ConnAccountId = ec2ConnAccountId;}
    
    public String getEc2ConnId() {return ec2ConnId;}    
    @DataBoundSetter
    public void setEc2ConnId(String ec2ConnId) {this.ec2ConnId = ec2ConnId;}    
    
    public boolean getRunConnector() {return runConnector;}
	@DataBoundSetter
	public void setRunConnector(boolean runConnector) {this.runConnector = runConnector;}
    
    public String getScannerName() {return scannerName;}
    @DataBoundSetter
    public void setScannerName(String scannerName) {this.scannerName = scannerName;}

    public String getScanName() {return scanName;}
    @DataBoundSetter
    public void setScanName(String scanName) {
    	scanName = StringUtils.isBlank(scanName) ? SCAN_NAME : scanName;
    	this.scanName = scanName;
    }
    
    public String getOptionProfile() {return optionProfile;}
    @DataBoundSetter
    public void setOptionProfile(String optionProfile) {this.optionProfile = optionProfile;}

    public String getNetwork() {return network;}
    @DataBoundSetter
    public void setNetwork(String network) {this.network = network;}

    public String getProxyServer() {return proxyServer;}
	@DataBoundSetter
	public void setProxyServer(String proxyServer) {this.proxyServer = proxyServer;}
	
	public int getProxyPort() {return proxyPort;}
	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		proxyPort = proxyPort <= 0 ? PROXY_PORT : proxyPort;
		this.proxyPort = proxyPort;
	}
	
	public String getProxyCredentialsId() { return proxyCredentialsId; }
	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) { this.proxyCredentialsId = proxyCredentialsId; }
		
	public boolean getUseProxy() {return useProxy;}
	@DataBoundSetter
	public void setUseProxy(boolean useProxy) {this.useProxy = useProxy;}
	
	public boolean getUseHost() {return useHost;}
	@DataBoundSetter
	public void setUseHost(boolean useHost) {this.useHost = useHost;}
	
	public boolean getUseEc2() {return useEc2;}
	@DataBoundSetter
	public void setUseEc2(boolean useEc2) {this.useEc2 = useEc2;}
	
	public boolean getDoExclude() {return doExclude;}
	@DataBoundSetter
    public void setDoExclude(boolean doExclude) {this.doExclude = doExclude;}
    
	public String getExcludeBy() {return excludeBy;}
	@DataBoundSetter
    public void setExcludeBy(String excludeBy) {this.excludeBy = excludeBy;}
	
	public String getExcludeList() {return excludeList;}	
	@DataBoundSetter
    public void setExcludeList(String excludeList) {this.excludeList = excludeList;}
	
	public boolean getEvaluatePotentialVulns() {return evaluatePotentialVulns;}
	@DataBoundSetter
	public void setEvaluatePotentialVulns(boolean evaluatePotentialVulns) {this.evaluatePotentialVulns = evaluatePotentialVulns;}
	
	public boolean getFailByPci() {return failByPci;}
	@DataBoundSetter
	public void setFailByPci(boolean failByPci) {this.failByPci = failByPci;}
	
	public String getWebhookUrl() {return webhookUrl;}
	@DataBoundSetter
    public void setWebhookUrl(String webhookUrl) {this.webhookUrl = webhookUrl;}
	
	public JsonObject getCriteriaAsJsonObject() {
    	JsonObject obj = new JsonObject();
    	
    	JsonObject failConditionsObj = new JsonObject();
    	Gson gson = new Gson();    	
    	if(failByQids) {
	    	if(this.qidList == null || this.qidList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("qids", empty);
	    	}else {
		    	List<String> qids = Arrays.asList(this.qidList.split(","));
		    	qids.replaceAll(String::trim);
		    	JsonElement element = gson.toJsonTree(qids, TypeToken.getParameterized(List.class, String.class).getType());		    	
		    	failConditionsObj.add("qids", element);
	    	}
    	}// end of failByQids
    	
    	if(failByCves) {
	    	if(this.cveList == null || this.cveList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("cve_id", empty);
	    	}else {
		    	List<String> cve = Arrays.asList(this.cveList.split(","));
		    	cve.replaceAll(String::trim);
		    	JsonElement element = gson.toJsonTree(cve, TypeToken.getParameterized(List.class, String.class).getType());
		    	failConditionsObj.add("cve_id", element);
	    	}
    	}// end of failByCves
    	
    	if(failByCvss) {
    		String baseField = this.byCvss;  
    		List<String> cvssCount = new ArrayList<String>();
    		cvssCount.add("0");
    		cvssCount.add("0.0");
    		double cvssBase = (this.cvssBase == null || this.cvssBase.isEmpty() || cvssCount.contains(this.cvssBase)) ? 0.0: Double.parseDouble(this.cvssBase);
    		
	    	if(cvssBase <= 0.0) {
	    		JsonElement empty = new JsonArray();	    		
	    		failConditionsObj.add(baseField, empty);
	    	}else {		    	
		    	failConditionsObj.addProperty(baseField, this.cvssBase);
	    	}
    	} // end of failByCvss
    	if(failBySev){
	    	JsonObject severities = new JsonObject();
	    	if(this.failBySev) {
	    		for(int i = this.bySev ; i <= 5; i++) {    			
	    			severities.addProperty(""+i,1);
	    		}
	    	}    	
	    	failConditionsObj.add("severities", severities);
    	}// end of failBySev
    	
    	if(this.doExclude) {
    		if("cve_id".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "cve_id");
    			List<String> cves = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(cves, TypeToken.getParameterized(List.class, String.class).getType());
    	    	failConditionsObj.add("excludeCVEs", element);
    		}
    		if("qid".equals(excludeBy)) {
    			failConditionsObj.addProperty("excludeBy", "qid");
    			List<String> qids = Arrays.asList(this.excludeList.split(","));
    	    	JsonElement element = gson.toJsonTree(qids, TypeToken.getParameterized(List.class, String.class).getType());
    	    	failConditionsObj.add("excludeQids", element);
    		}    		
    	}
    	
    	if(failByPci) {
    		failConditionsObj.addProperty("failByPci", failByPci);
    	}// end of failByPci
    	
    	failConditionsObj.addProperty("evaluatePotentialVulns", evaluatePotentialVulns);    	
    	
    	obj.add("failConditions",failConditionsObj);    	
    	return obj;
	}// End of getCriteriaAsJsonObject
	
	/* End of Getter Setters*/
	
	 @DataBoundConstructor
	    public VMScanNotifier(String apiServer, String credsId, String hostIp, String ec2ConnDetails, String ec2Id, 
			String scannerName, String scanName, String optionProfile, String network, String proxyServer,
	    		int proxyPort, String proxyCredentialsId, boolean useProxy, boolean useHost, boolean useEc2,
	    		String pollingInterval, String vulnsTimeout, int bySev, boolean failBySev, boolean failByQids, 
	    		boolean failByCves, String qidList, String cveList, boolean failByCvss, String byCvss, 
	    		String cvssBase, boolean doExclude, String excludeBy, String excludeList, boolean evaluatePotentialVulns, 
	    		boolean failByPci,String webhookUrl, boolean runConnector) {
		 	 	
		 	if(!StringUtils.isBlank(apiServer)) 
		 	{
		 		this.apiServer = apiServer;
		 	}
	        
	        
	        this.credsId = credsId;        
	        this.scanName = scanName;
	        this.optionProfile = optionProfile;
	        this.scannerName = scannerName;
	        
	        
	        if(useProxy) {
	        	this.useProxy = useProxy;
		        this.proxyServer = proxyServer;
		        this.proxyPort = proxyPort;
		        this.proxyCredentialsId = proxyCredentialsId;
	        }
	        if(useHost) {
	        	this.useHost = useHost;
	        	this.hostIp = hostIp;
	        	this.network = network;
	        	}
	        
	        
	        if(useEc2) {
	        	this.useEc2 = useEc2;
	        	this.ec2Id = ec2Id;
		        this.runConnector = runConnector;
		        if(ec2ConnDetails == null || ec2ConnDetails.isEmpty()) {
		        	this.ec2ConnDetails = "{\"NoConnectorSelected\":{\"awsAccountId\":0,\"id\":0,\"connectorState\":0}}";
		        }else {
		        	this.ec2ConnDetails = ec2ConnDetails;
		        }      
		        JsonParser jsonParser = new JsonParser();
	    		JsonObject jo = (JsonObject)jsonParser.parse(this.ec2ConnDetails);    		
	    		this.ec2ConnName = jo.keySet().toString().replaceAll("\\[|\\]", "");    		
	    		JsonObject i =  jo.get(this.ec2ConnName).getAsJsonObject();    		
	    		this.ec2ConnAccountId = i.get("awsAccountId").getAsString();
	    		this.ec2ConnId = i.get("id").getAsString();
	        }
	        
	        this.pollingInterval = pollingInterval;
	        this.vulnsTimeout = vulnsTimeout;
	                
	        if(failBySev) {        	
	        	this.bySev = bySev;
	        	this.failBySev = failBySev;        	
	        }        
	        
	        if(failByQids) {
	        	this.failByQids = failByQids;
	        	this.qidList = qidList;
	        }
	        if(failByCves) {
	        	this.failByCves = failByCves;
	        	this.cveList = cveList;
	        }
	        if(failByCvss) {
	        	this.failByCvss = failByCvss;
	        	this.byCvss = byCvss;
	        	this.cvssBase = cvssBase;
	        }
	        
	    	if(doExclude) {
	    		this.doExclude = doExclude;
	    		this.excludeBy = excludeBy;
	    		this.excludeList = excludeList;
	    	}
	    	
	    	if(failByPci) {
	    		this.failByPci = failByPci;
	    	}
	    	
	    	if(failBySev || failByQids || failByCves || failByCvss || failByPci) {
	    		this.evaluatePotentialVulns = evaluatePotentialVulns;    		   		
	    	}
	    	
	    	if(!StringUtils.isBlank(webhookUrl)) {
	    		this.webhookUrl = webhookUrl;
	    	}
	    } // End of Constructor 
	 	
	 	
	 
	 /*1st Nested class*/
    @Extension
    @Symbol(value = { "qualysVulnerabilityAnalyzer" })
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {    	
        private static final String URL_REGEX = "^(https?)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private static final String WEBHOOK_URL_REGEX = "(https?:\\/\\/(?:www\\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\\.[^\\s]{2,}|www\\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\\.[^\\s]{2,}|https?:\\/\\/(?:www\\.|(?!www))[a-zA-Z0-9]+\\.[^\\s]{2,}|www\\.[a-zA-Z0-9]+\\.[^\\s]{2,})";
        private static final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private static final String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";
        private static final String HOST_IP = "^\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
        private static final String awsAccountId = "awsAccountId";
        private static final String utf8Error = "Provide valid UTF-8 string value.";
        private static final String displayName = "Scan host/instances with Qualys VM";
        private JsonObject ctorNameList = new JsonObject();
        Helper h = new Helper();
        
    	@Override
        public String getDisplayName() {
    		return displayName;
        }

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}
		

	    public ListBoxModel doFillPlatformItems() {
        	ListBoxModel model = new ListBoxModel();
        	for(Map<String, String> platform: getPlatforms()) {
        		Option e = new Option(platform.get("name"), platform.get("code"));
            	model.add(e);
        	}
        	return model;
        }
		
		public FormValidation doCheckApiServer(@QueryParameter String apiServer) {
	    	if(isNonUTF8String(apiServer)) {
	        	return FormValidation.error(utf8Error);
	        }
	    	try {
	    		String server = apiServer != null ? apiServer.trim() : "";
	        	Pattern patt = Pattern.compile(URL_REGEX);
	            Matcher matcher = patt.matcher(server);
	        	
	            if (!(matcher.matches())) {
	                return FormValidation.error("Server name is not valid!");
	            } else {
	            	 return FormValidation.ok();
	            }
	        } catch (Exception e) {
	            return FormValidation.error(e.getMessage());
	        }
	    } // End of doCheckApiServer FormValidation

        public FormValidation doCheckCredsId(@QueryParameter String credsId) {
        	 try {
                 if (credsId.trim().equals("")) {
                     return FormValidation.error("API Credentials cannot be empty.");
                 } else {
                     return FormValidation.ok();
                 }
             } catch (Exception e) {
                 return FormValidation.error(e.getMessage());
             }
        }// End of doCheckCredsId FormValidation
        
        @POST
        public ListBoxModel doFillCredsIdItems(@AncestorInPath Item item, @QueryParameter String credsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(credsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(credsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(credsId));
        
        } // End of doFillCredsIdItems FormValidation
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
        	if(isNonUTF8String(proxyServer)) {
            	return FormValidation.error(utf8Error);
            }
        	try {
            	Pattern patt = Pattern.compile(PROXY_REGEX);
                Matcher matcher = patt.matcher(proxyServer);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter valid server url!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        
        } // End of doCheckProxyServer FormValidation
        
        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
        	try {
        		if (proxyPort != null && !proxyPort.trim().isEmpty()) {
        			int proxyPortInt = Integer.parseInt(proxyPort);
        			if(proxyPortInt < 1 || proxyPortInt > 65535) {
        				return FormValidation.error("Enter a valid port number!");
        			}
        		}else {
        			return FormValidation.error("Enter a valid port number!");
        		}
        	} catch (RuntimeException e) {
        		return FormValidation.error("Enter valid port number!");
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid port number!");
        	}
        	return FormValidation.ok();
        
        } // End of doCheckProxyPort FormValidation
        
        @POST
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
                	return result.add(proxyCredentialsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(proxyCredentialsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(proxyCredentialsId));
        
        } // End of doFillProxyCredentialsIdItems FormValidation
        
        public FormValidation doCheckHostIp(@QueryParameter String hostIp) {
        	try {
        		if (hostIp != null && StringUtils.isNotBlank(hostIp)) 
        		{
        			if (hostIp.startsWith("env.")) {
        				return FormValidation.ok();
					}
        			Pattern patt = Pattern.compile(HOST_IP);
                    Matcher matcher = patt.matcher(hostIp);                	
                    if (!(matcher.matches())) {
                        return FormValidation.error("Host IP is not in valid format!");
                    } else {
                    	 return FormValidation.ok();
                    }
        		}else {        			
        			return FormValidation.error("Provide a valid Host IP.");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid Host Ip!");
        	}        	
        
        } // End of doCheckHostIp FormValidation
 
        public FormValidation doCheckScanName(@QueryParameter String scanName) {
        	if(isNonUTF8String(scanName)) {
            	return FormValidation.error(utf8Error);
            }
        	try {
                if (scanName.trim().equals("")) {
                    return FormValidation.error("Scan Name cannot be empty.");
                } else {
                	if(scanName.length() > 256) {
                		return FormValidation.error("Scan Name length must be of 256 or less characters.");
                	}
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        
        } // End of doCheckScanName FormValidation     
        
        public FormValidation doCheckEc2Id(@QueryParameter String ec2Id) {
        	if(isNonUTF8String(ec2Id)) {
        		return FormValidation.error("Provide valid EC2 Instance Id.");
        	}
        	try {
        		if (ec2Id.trim().equals("")) {
        			return FormValidation.error("EC2 Instance Id cannot be empty.");
        		} else {
        			return FormValidation.ok();
        		}
        	} catch (Exception e) {
        		return FormValidation.error(e.getMessage());
        	}      	
        
        } // End of doCheckEc2Id FormValidation
        
        public FormValidation doCheckScannerName(@QueryParameter String scannerName) {
	    	try {
	    		if (scannerName.trim().equals("")) {
	    			return FormValidation.error("Select a Scanner Name.");
	    		} else {
	    			return FormValidation.ok();
	    		}
	    	} catch (Exception e) {
	    		return FormValidation.error(e.getMessage());
	    	}
    
        } // End of doCheckScannerName FormValidation
        
        public FormValidation doCheckQidList(@QueryParameter String qidList) {
        	if (qidList == null || qidList.isEmpty()) {
        		return FormValidation.ok();
        	}
        	try {
        		if(!Helper.isValidQidList(qidList)) {
            		return FormValidation.error("Enter valid QID range/numbers!");
            	}
            	return FormValidation.ok();
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid QID range/numbers! Error:" + e.getMessage());
        	}        	
        
        } // End of doCheckQidList FormValidation
        
        public FormValidation doCheckCveList(@QueryParameter String cveList) {
        	if(!Helper.isValidCVEList(cveList)) {
        		return FormValidation.error("Enter valid CVEs! Given: " + cveList);
        	}
        	return FormValidation.ok();
        
        } // End of doCheckCveList FormValidation
        
        public FormValidation doCheckCvssBase(@QueryParameter String cvssBase) {
    		if (cvssBase != null && !cvssBase.isEmpty()) {        			
    			double cvssDouble = 0.0;
    			try {
    				cvssDouble = Double.parseDouble(cvssBase);
					if(cvssDouble < 0.0 || cvssDouble > 10.0) {
						return FormValidation.error("Enter a number in range of 0.0 to 10.0");
					}
				} catch (NumberFormatException e) {
					return FormValidation.error("Input is not a valid number. " + e.getMessage());        				    
				} catch (RuntimeException e) {
					return FormValidation.error("Enter valid number!");
	        	}  catch(Exception e) {
	        		return FormValidation.error("Enter valid number!");
	        	}        			
    		}
        	
        	return FormValidation.ok();        	
        
        } // End of doCheckCvssBase FormValidation
      
        public FormValidation doCheckPollingInterval(@QueryParameter String pollingInterval) {
            try {
            	String pollingIntervalVal = pollingInterval.trim(); 
            	if (pollingIntervalVal.equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(pollingIntervalVal);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + pollingInterval + ", reason = " + e);
            }
            return FormValidation.ok();
        
        } // End of doCheckPollingInterval FormValidation

        public FormValidation doCheckVulnsTimeout(@QueryParameter String vulnsTimeout) {
            String vulnsTimeoutVal = vulnsTimeout.trim();
        	try {
            	 if (vulnsTimeoutVal.equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(vulnsTimeoutVal);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 } else {
                     return FormValidation.ok();
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + vulnsTimeout + ", reason = " + e);
            }
        
        } // End of doCheckVulnsTimeout FormValidation
        
        public FormValidation doCheckExcludeList(@QueryParameter String excludeList, @QueryParameter String excludeBy) {
        	try {        		
        		if (excludeList != null && !excludeList.isEmpty() && 
        				excludeBy.equalsIgnoreCase("cve_id") && !Helper.isValidCVEList(excludeList)) {    			
    				return FormValidation.error("Enter valid CVEs! Given:" + excludeList);		           			
        		}
        		else if (excludeList != null && !excludeList.isEmpty() &&
        				!excludeBy.equalsIgnoreCase("cve_id") && !Helper.isValidQidList(excludeList)){
        			return FormValidation.error("Enter valid QID range/numbers!");
    			} else {
    				return FormValidation.ok();
    			}
        	} catch (RuntimeException e) {
        		return FormValidation.error("Enter valid value!");
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid value!");
        	} 
        
        } // End of doCheckExcludeList FormValidation
        
        public FormValidation doCheckWebhookUrl(@QueryParameter String webhookUrl) {
            try {
            	if(StringUtils.isEmpty(webhookUrl)) {
            		return FormValidation.ok();
            	}
            	Pattern patt = Pattern.compile(WEBHOOK_URL_REGEX);
                Matcher matcher = patt.matcher(webhookUrl);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Webhook Url is not valid!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        
        } //end of doCheckWebhookUrl FormValidation
        
        public FormValidation doCheckNetwork(@QueryParameter String network) {
        	try {
	    		if (network.trim().equals("")) {
	    			return FormValidation.error("Select a Network Name.");
	    		} else if (network.trim().equals("NETWORK_NOT_FOUND")) {
	    			return FormValidation.error("There are currently no networks assigned to you. Contact your System Administrator to assign custom networks");
	    		} else {
	    			return FormValidation.ok();
	    		}
	    	} catch (Exception e) {
	    		return FormValidation.error(e.getMessage());
	    	}
        } //end of doCheckNetwork FormValidation
        
        @POST
        public FormValidation doCheckConnection(@QueryParameter String platform,@QueryParameter String apiServer, @QueryParameter String credsId,
        		@QueryParameter String proxyServer, @QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @AncestorInPath Item item) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	try {
            	int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        		String server = apiServer != null ? apiServer.trim() : "";  
        		if(!platform.equalsIgnoreCase("pcp")) {
            		Map<String, String> platformObj = Helper.platformsList.get(platform);
            		server = platformObj.get("url");
            		logger.info("Using qualys API Server URL: " + apiServer);
            	}
        		QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
        		
        		if(platform.equalsIgnoreCase("pcp")) 
        		{
        			client.testConnection();
        		}
        		else
        		{	
        			client.testConnectionUsingGatewayAPI();
        		}
            	return FormValidation.ok("Connection test successful!");
                
            } catch (Exception e) {        	
            	return FormValidation.error("Connection test failed. (Reason: " + e.getMessage() + ")");
            }
        
        } // End of doCheckConnection FormValidation 
       
        @POST
        public ListBoxModel doFillScannerNameItems(@AncestorInPath Item item,@QueryParameter String platform,@QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, 
        		@QueryParameter boolean useEc2, @QueryParameter boolean useHost, @QueryParameter String network) {

        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	JsonObject scannerList = null;
        	Option e1 = new Option("Select the scanner appliance", "External");
        	model.add(e1);
        	try {
        		if(filledInputs(platform,apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        			String server = apiServer != null ? apiServer.trim() : "";
            		if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                		logger.info("Using qualys API Server URL: " + apiServer);
                	}
        			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
        			if(useEc2) {
            			logger.info("Fetching EC2 Scanner Names list ... ");
            			scannerList = client.scannerName(false, network);
            		} else {
            			logger.info("Fetching Scanner Names list ... ");
            			scannerList = client.scannerName(true, network);
            		}
        			for (String name : scannerList.keySet()) {    				   				
            			JsonObject jk = scannerList.get(name).getAsJsonObject();
    	        		String scanStatus = jk.get("status").getAsString();
    	        		String scanAccId = jk.get("accountId").getAsString();
    	        		if(useEc2) {
    	        			Option e = new Option(name + " (Account Id: " + scanAccId +  " | Status: "+scanStatus+")", name);
    	        			model.add(e);
    	        		}else {
    	        			Option e = new Option(name + " (Status: "+scanStatus+")", name);
    	        			model.add(e);
    	        		}
            		}  
        			if(useHost && network != null && !network.isEmpty() && !network.trim().equals("NETWORK_NOT_FOUND") && !network.trim().equals("UNAUTHORIZED_ACCESS") && !network.trim().equals("ACCESS_FORBIDDEN"))
        			{
        				Option e2 = new Option("All Scanners in Network", "All_Scanners_in_Network");
        				model.add(e2);
        			}
        		}// End of if        		
        	} catch(Exception e) {    		
    			StandardListBoxModel errorModel = new StandardListBoxModel();
        		logger.warning("Error to get scanner list. " + e.getMessage());
        		Option ee = new Option(e.getMessage(), "");
        		errorModel.add(ee);
    			return errorModel;
        	}
        	model.sort(Helper.getOptionItemmsComparator());
        	return model;
        }// End of doFillScannerItems ListBoxModel
        
        @POST
        public ListBoxModel doFillNetworkItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	
        	Option e1 = new Option("Select the network", "");
        	model.add(e1);
        	try {
        		if(filledInputs(platform,apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        			String server = apiServer != null ? apiServer.trim() : "";
            		if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                		logger.info("Using qualys API Server URL: " + apiServer);
                	}
        			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
            		logger.info("Fetching Network list ... ");
            		JsonArray networkList = client.getNetworkList();
            		for (JsonElement n : networkList) {
            			JsonObject network = n.getAsJsonObject();
            			Option e = new Option(network.get("name").getAsString(), network.get("id").getAsString());
            			model.add(e);
            		}
        		}// End of if
        	} catch(Exception e) {
        		StandardListBoxModel errorModel = new StandardListBoxModel();
        		logger.warning("Error to get Network list. " + e.getMessage());
        		Option ee;
        		if (e.getMessage().contains("UNAUTHORIZED ACCESS")) {
        			ee = new Option("UNAUTHORIZED ACCESS - Please provide valid Qualys credentials", "UNAUTHORIZED_ACCESS");
        		}
        		else if(e.getMessage().contains("ACCESS FORBIDDEN")) {
        			ee = new Option("Enable the custom network list option for your subscription. For this scan, a predefined network will be used", "ACCESS_FORBIDDEN");
        		}
        		else if (e.getMessage().contains("Network not found")) {
        			ee = new Option("There are currently no networks assigned to you. Contact your System Administrator to assign custom networks", "NETWORK_NOT_FOUND");
        		} else {
        			ee = new Option(e.getMessage(), "");
        		}
        		
        		errorModel.add(ee);
    			return errorModel;
        	}
        	model.sort(Helper.getOptionItemmsComparator());
        	return model;
        
        } // End of doFillOptionProfileItems ListBoxModel


        @POST
        public ListBoxModel doFillOptionProfileItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();

        	Option e1 = new Option("Default scan option profile", "Initial Options");
        	model.add(e1);        	
        	try {
        		if(filledInputs(platform,apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        			String server = apiServer != null ? apiServer.trim() : "";
            		if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                		logger.info("Using qualys API Server URL: " + apiServer);
                	}
        			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);
            		logger.info("Fetching Option Profiles list ... ");
            		Set<String> nameList = client.optionProfiles();	        		
            		for (String name : nameList) {
            			Option e = new Option(name, name);
            			model.add(e);	        		
            		}	        		
        		}// End of if        		
        	} catch(Exception e) {    
        		StandardListBoxModel errorModel = new StandardListBoxModel();
        		logger.warning("Error to get option profile list. " + e.getMessage());
        		Option ee = new Option(e.getMessage(), "");
        		errorModel.add(ee);
    			return errorModel;
        	}        	
        	model.sort(Helper.getOptionItemmsComparator());
        	return model;
        
        } // End of doFillOptionProfileItems ListBoxModel
        
        @POST
        public ListBoxModel doFillEc2ConnDetailsItems(@AncestorInPath Item item,@QueryParameter String platform ,@QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @QueryParameter boolean useEc2) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	Option e1 = new Option("--select--", "");
        	model.add(e1); 
        	try {        		
        		if(useEc2 && filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
        			String server = apiServer != null ? apiServer.trim() : ""; 
            		if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                		logger.info("Using qualys API Server URL: " + apiServer);
                	}
        			QualysVMClient client = h.getClient(useProxy, server, credsId, proxyServer, proxyPortInt, proxyCredentialsId, item);    			
        			logger.info("Fetching Ec2 connector name list ... ");	        		
            		ctorNameList = client.getConnector();
            		for (String name : ctorNameList.keySet()) {
            			JsonObject jk = ctorNameList.get(name).getAsJsonObject();	        			
    	        		JsonObject ConName = new JsonObject();
    	        		JsonObject ConNameDetails = new JsonObject();
    	        		String accId = jk.get(awsAccountId).getAsString();
    	        		String connectorState = jk.get("connectorState").getAsString();
    	        		ConNameDetails.addProperty(awsAccountId, accId);
    	        		ConNameDetails.addProperty("id", jk.get("id").getAsString());
    	        		ConName.add(name,ConNameDetails);
    	        		Option e = new Option(name + " (Account Id:" + accId + " | State:"+connectorState+")", ConName.toString());        			
            			model.add(e);
            		}
        		}// End of if        		
        	} catch(Exception e) {
        		Option e2 = new Option(e.getMessage(), "");
    			model.add(e2);			
    			logger.warning("There is an error while fetching the connectors list. " + e);
        		return model;
        	}        	
        	model.sort(Helper.getOptionItemmsComparator());
        	return model;
        
        } // End of doFillEc2ConnNameItems ListBoxModel
        
        public boolean isNonUTF8String(String string) {
        	if(string != null && !string.isEmpty()) {
            	try 
            	{
            	    string.getBytes(java.nio.charset.StandardCharsets.UTF_8);        	    
            	} 
            	catch (Exception e){        			    		
    	    	    return true;
            	}
        	}
        	return false;
        } 
        
        public boolean filledInputs(String platform,String apiServer, String credsId, boolean useProxy, String proxyServer, String proxyPort) {			
        	if(platform.equalsIgnoreCase("pcp") && StringUtils.isBlank(apiServer)) return false;
        	if(StringUtils.isBlank(credsId)) return false;
    		if(useProxy && StringUtils.isBlank(proxyServer)) return false;
        	return true;
        }// End of filledInputs method
        
        public List<Map<String, String>> getPlatforms() {
        	List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        	for (Map.Entry<String, Map<String, String>> platform : Helper.platformsList.entrySet()) {
                Map<String, String>obj = platform.getValue();
                result.add(obj);
            }
            return result;
        }
    }
	/* End of DescriptorImpl class */
    
    /*From this point the Scan Run process is starts.
     * The VMScanLauncher class will be used here.*/
    /*######################################*/
    
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    public String getPluginVersion() {
    	try {
     	   MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model;
            if ((new File("pom.xml")).exists()) {
            	InputStream inputStream = new FileInputStream("pom.xml");
            	model = reader.read(new InputStreamReader(inputStream, "UTF-8"));
            }
            else
              model = reader.read(
                new InputStreamReader(
                		VMScanNotifier.class.getResourceAsStream(
                    "/META-INF/maven/com.qualys.plugins/qualys-vm/pom.xml"
                  ), "UTF-8"
                )
              );
            return model.getVersion();
        } catch (RuntimeException e) {
        	logger.info("Exception while reading plugin version; Reason :" + e.getMessage());
      	   	return "unknown";
        } catch(Exception e) {
     	   logger.info("Exception while reading plugin version; Reason :" + e.getMessage());
     	   return "unknown";
        }
	}//end of getPluginVersion method
   
    @SuppressWarnings("null")
	@Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher, @Nonnull TaskListener taskListener) throws InterruptedException, IOException {    	
    	long startTime = System.currentTimeMillis();
    	Item project = null;
    	logger.info("Triggered build #" + run.number);
    	try {
    		String version = getPluginVersion();
    		taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" " +pluginName+" (version-"+ version +") started.");
    		logger.info(pluginName+" (version-"+ version +") started.");
    	} catch (RuntimeException e) {
    		taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" " +pluginName+" started.");
    		logger.info(pluginName+" started.");
    	} catch(Exception e) {
    		taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) +" " +pluginName+" started.");
    		logger.info(pluginName+" started.");    		
    	}
    	taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Started.");
    	
    	//This method will extract ec2Id and hostIp from environment variables
    	extractEnvVariables(run.getEnvironment(taskListener), taskListener);
    	
    	
    	if ((useHost && StringUtils.isNotBlank(hostIp)) || (useEc2 && StringUtils.isNotBlank(ec2Id))) {
             try {
            	 project = run.getParent();            	            	 
            	 launchHostScan(run, taskListener, project);
             } catch (Exception e) {
            	 if(e.toString().equalsIgnoreCase("java.lang.Exception")) {
            		 throw new AbortException("Exception in "+pluginName+" scan result. Finishing the build."); 
            	 }else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {
                	 logger.log(Level.SEVERE,"Error: User Aborted");                	 
                     throw new AbortException("Exception in "+pluginName+" scan result: User Aborted"); 
            	 }else {
                	 logger.log(Level.SEVERE,"Error: "+e.getMessage());            	 
                     throw new AbortException("Exception in "+pluginName+" scan result: Finishing the build. Reason: " + e.getMessage());            		 
            	 }                 
             }finally {
            	 long endTime = System.currentTimeMillis();
            	 long time = endTime - startTime;	            	 
            	 taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Total time taken to complete the build: " + Helper.longToTime(time));
            	 logger.info("Total time taken to complete the build: " + Helper.longToTime(time)); 
             }
        } else {
        	taskListener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " No Host IP or EC2 Instance Id Configured.");
        	throw new AbortException("Host IP or EC2 Instance Id can't be set to null or empty.");
        }    	
        return;
    }// End of perform method

	public void launchHostScan(Run<?, ?> run, TaskListener listener, Item project) throws Exception {    	 	
    	// Set username and password for the portal		
    	JsonObject connectorState = new JsonObject();
    	connectorState.addProperty("state", true);
    	JsonObject instanceState = new JsonObject();
    	instanceState.addProperty("endpoint", "Unknown");
    	Helper h = new Helper();
    	QualysAuth auth = null;
    	boolean isFailConditionsConfigured = false;
    	String instanceStatus = "";
    	
    	Map<String, String> platformObj = Helper.platformsList.get(platform);

    	//set apiServer URL according to platform
    	if(!platform.equalsIgnoreCase("pcp")) {
    		setApiServer(platformObj.get("url"));
    		logger.info("Using qualys API Server URL: " + apiServer);
    	}
    	listener.getLogger().println("Qualys Platform: " + platform +". Using Qualys API server: " + apiServer);
    	QualysVMClient client = h.getClient(useProxy, apiServer, credsId, proxyServer, proxyPort, proxyCredentialsId, project);
    	try {
    		String log = " Testing connection with Qualys API Server...";
    		String log1 = " Test connection successful.";
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log);
    		logger.info(log);
    		if(platform.equalsIgnoreCase("pcp")) 
    		{
    			client.testConnection();
    		}
    		else
    		{	
    			client.testConnectionUsingGatewayAPI();
    		}
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + log1);
    		logger.info(log1);
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Test connection failed. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of test connection
    	try {
	    	// check if Fail conditions are configured or not for the scan.	    	   	
	    	if(failByQids || failByCves || failByCvss || this.failBySev || this.failByPci) {
	    		isFailConditionsConfigured = true;
	    	}
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while setting fail conditions. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of setting the Fail Conditions
    	
    	try {
    		auth = h.getQualysAuth(useProxy, apiServer, credsId, proxyServer,
    				proxyPort, proxyCredentialsId, project);			
    	}catch(Exception e) {
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while setting Qualys Credentials. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}//end of setting Qualys Credentials
    	
    	try {
	    	if (useEc2) {    		
	    		VMScanEc2ConnectorLauncher ctor = new VMScanEc2ConnectorLauncher(run, listener,    				
	        			pollingInterval,vulnsTimeout, auth,useEc2, this.ec2ConnId, this.ec2ConnName);
	    		// Get instance state and endpoint
	    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Checking the state of instance(" + this.ec2Id+ ") with instance account(" + this.ec2ConnAccountId+ ")");	    		
	    		// Get state of Instance
	    		instanceState = ctor.checkInstanceState(this.ec2IdValue, this.ec2ConnAccountId);
	    		instanceStatus = instanceState.get("instanceState").getAsString();	    		
	    		
	    		if (instanceState.get("count").getAsInt() == 0) {
		    		// Get state of connector
		    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Checking the state of connector: " + this.ec2ConnName);
		    		String ec2ConnState = ctor.getCtorStatus(this.ec2ConnId, true);	    		
		    		// log message for checkbox status
	    			String logMsg = " Run connector checkbox: " +( runConnector ? "checked" : "unchecked");
	    			logger.info(logMsg);
	    			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + logMsg);	    			
		    		    		
		    		//If checkbox is checked, decide weather to run the connector depending upon the connector state and instance state
	    			if(!runConnector && !instanceStatus.equalsIgnoreCase("RUNNING")){
	    				// If check box is not check and instance is not running, abort the build 
	    				throw new Exception("Instance state is: "+instanceStatus+". Could not find the provided instance ID with a given EC2 configuration. "
	    						+ "The user might have provided the wrong instance/connector/scanner details. "
	    						+ "Re-check the EC2 details provided for the scan.");
	    			} else if(runConnector && runCtorDecision(ec2ConnState, listener)) {
	    				//if the connector is not in ENDING/PROCESSING/QUEUED/RUNNING, run connector	
	    				logger.info(pluginName+" task - Started running the Ec2 Connector: " + ec2ConnName);
		    			ctor.runCtor();
		        		logger.info(pluginName+" task - Finished running Ec2 Connector: " + ec2ConnName);
		    		} else if(runConnector && !runCtorDecision(ec2ConnState, listener)) {
		    			//if the connector is in PENDING/PROCESSING/QUEUED/RUNNING, do polling	    	    	
		    			ctor.ctorPolling(ec2ConnId, false);
		    		}
	    		}
	    	}// end of checking if EC2 is selected
    	}catch(Exception e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while checking ec2 details. Reason: " + e.getMessage());
    		for (StackTraceElement traceElement : e.getStackTrace())
                logger.info("\tat " + traceElement); 
    		throw new Exception(e.getMessage());
    	}//end of checking ec2 details
    	
    	try {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Started.");
    		logger.info(pluginName+" scan task - Started.");    		  		
    		VMScanLauncher launcher = new VMScanLauncher(run, listener, hostIpValue, ec2IdValue, ec2ConnName, 
    				instanceState.get("endpoint").getAsString(), 
        			scannerName, scanName, optionProfile, isFailConditionsConfigured, pollingInterval, 
        			vulnsTimeout, getCriteriaAsJsonObject(), useHost, useEc2, 
        			auth, webhookUrl, byCvss, network);
        	
        	launcher.getAndProcessLaunchScanResult();    	
            listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " "+pluginName+" scan task - Finished.");        
            logger.info(pluginName+" task - Finished.");
    	}catch(NullPointerException e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error while launching the scan. Could not find the provided instance ID with a given EC2 configuration. The user might have provided the wrong instance/connector/scanner details. Re-check EC2 details provided for the scan.\nAborting the build!!!");    		
    		throw new Exception(e.getMessage());
    	}catch(Exception e) {
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Build stopped. Reason: " + e.getMessage());    		 
    		throw new Exception(e.getMessage());
    	}//end of launching the scan
    } // End of launchHostScan method
	
	public boolean runCtorDecision(String ec2ConnState, TaskListener listener) throws Exception {
		boolean run = false;
		List<String> conRunList = new ArrayList<String>();
    	List<String> conNoRunList = new ArrayList<String>();
    	conRunList.add("FINISHED_ERRORS");
    	conRunList.add("ERROR");    	
    	conRunList.add("INCOMPLETE");
    	conRunList.add("FINISHED_SUCCESS");
    	conRunList.add("SUCCESS");
    	conNoRunList.add("RUNNING");
    	conNoRunList.add("PENDING");
    	conNoRunList.add("QUEUED");
    	conNoRunList.add("PROCESSING");    	
    	
    	if (ec2ConnState.equalsIgnoreCase("DISABLED")) {
    		logger.warning("Connector is in "+ec2ConnState+" state. Aborting!!");
			throw new Exception("Connector is in "+ec2ConnState+" state. Aborting!!");			
		}else if (conNoRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is "+ec2ConnState+". Not running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "+ec2ConnState+". Not running the connector!");
			run = false;
		} else if(conRunList.contains(ec2ConnState)) {
			logger.warning("Connector state is "+ec2ConnState+". Running the connector!");
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Connector state is "+ec2ConnState+". Running the connector!");
			run =  true;
		}
		return run;
	}
	
	private void extractEnvVariables(EnvVars envVars, TaskListener listener) throws AbortException {
		if (useHost && hostIp != null && !hostIp.isEmpty()) {
			if (hostIp.startsWith("env.") && envVars != null && !envVars.isEmpty()) {
				String envHostIpKey = hostIp.replaceFirst("env.", "");
				hostIpValue = envVars.get(envHostIpKey);
				if (hostIpValue != null && !hostIpValue.isEmpty()) {
					logger.info("Host IP value from environment variable is - " + hostIpValue);
					listener.getLogger().println(new Timestamp(System.currentTimeMillis())
							+ " Host IP value from environment variable is - " + hostIpValue);
				} else {
					throw new AbortException("Host IP - Environment variable " + envHostIpKey + " is missing !!");
				}
			} else {
				hostIpValue = hostIp;
			}

		}
		if (useEc2 && ec2Id != null && !ec2Id.isEmpty()) {
			if (ec2Id.startsWith("env.") && envVars != null && !envVars.isEmpty()) {
				String envEc2IdKey = ec2Id.replaceFirst("env.", "");
				ec2IdValue = envVars.get(envEc2IdKey);
				if (ec2IdValue != null && !ec2IdValue.isEmpty()) {
					logger.info("EC2 ID value from environment variable is - " + ec2IdValue);
					listener.getLogger().println(new Timestamp(System.currentTimeMillis())
							+ " EC2 ID value from environment variable is - " + ec2IdValue);
				} else {
					throw new AbortException("Host IP - Environment variable " + envEc2IdKey + " is missing !!");
				}
			} else {
				ec2IdValue = ec2Id;
			}

		}
	}
	
} // End of VMScanNotifier class