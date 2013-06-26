package eu.dime.userresolver.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.management.modelmbean.XMLParseException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.ibm.zurich.idmx.dm.Credential;
import com.ibm.zurich.idmx.dm.MasterSecret;
import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.issuance.Message;
import com.ibm.zurich.idmx.issuance.Recipient;
import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Prover;
import com.ibm.zurich.idmx.utils.Constants;
import com.ibm.zurich.idmx.utils.Parser;
import com.ibm.zurich.idmx.utils.XMLSerializer;

import eu.dime.userresolver.client.entities.RoundTwoRequestData;
import eu.dime.userresolver.client.entities.RoundTwoResponseData;
import eu.dime.userresolver.client.entities.RoundZeroRequestData;
import eu.dime.userresolver.client.entities.RoundZeroResponseData;
import eu.dime.userresolver.client.entities.StructureInformation;
import eu.dime.userresolver.client.utils.IdemixUtils;

public class IdemixClient {
	private static final Logger LOG = 
			LoggerFactory.getLogger(IdemixClient.class);
	
	private HttpClient httpClient = new DefaultHttpClient();
	
	private Gson gson = new Gson();
	
	private String issuerEndpoint;
	private StructureInformation structureInformation;
	
	public IdemixClient(String issuerEndpoint) throws IOException{
		this.issuerEndpoint = issuerEndpoint;
		structureInformation = requestStructureInformation();
		LOG.debug("Issuer structure information: {}", structureInformation);
	}
	
	public String generateMasterSecret() throws IllegalStateException{
		try {
			URI gpURI = new URI(structureInformation.getIssuerURL() 
					+ structureInformation.getGroupParameterURI());
			
			MasterSecret masterSecret = new MasterSecret(gpURI);
			
			return XMLSerializer.getInstance().serialize(masterSecret);
		} catch(URISyntaxException e) {
			throw new IllegalStateException("Unvalid groupparameters URI");
		}
				
	}
	
	public Set<String> getCredentialNames() {
		return structureInformation.getCredentialStrucutures().keySet();
	}
	
	public String getCredential(String msString, String credentialName, 
			Map<String, String> values) 
					throws IOException, IllegalArgumentException{
		
		RoundZeroRequestData roundZeroRequestData = 
				new RoundZeroRequestData(credentialName, values);
		RoundZeroResponseData roundZeroResponseData = 
				requestRound0(roundZeroRequestData);
		
		MasterSecret masterSecret = 
				(MasterSecret) Parser.getInstance().parse(msString);
		
		String strucString = requestCredentialStructure(credentialName);
		IssuanceSpec issuanceSpec = getIssuanceSpec(credentialName);
		
		Values idxValues = 
				IdemixUtils.generateIdemixValues(
						strucString, issuanceSpec, values);
		
		Recipient recipient = new Recipient(
				issuanceSpec, masterSecret, idxValues);
		
		Message message = (Message) Parser.getInstance().parse(
				roundZeroResponseData.getMessage());
		
		message = recipient.round1(message);
		
		String msgString = XMLSerializer.getInstance().serialize(message);
		
		RoundTwoRequestData roundTwoRequestData = 
				new RoundTwoRequestData(msgString);
		RoundTwoResponseData roundTwoResponseData = requestRound2(
				roundZeroResponseData.getIssuanceId(), roundTwoRequestData);
		
		message = (Message) Parser.getInstance().parse(
				roundTwoResponseData.getMessage());
		
		Credential credential = recipient.round3(message);
		String csString = XMLSerializer.getInstance().serialize(credential);
		
		return csString;
	}
	
	public String compileProof(String nonce, String masterSecret, 
			Map<String, String> credentials, String proofSpec) 
					throws IllegalArgumentException{
		BigInteger idxNonce;
		try {
			idxNonce = new BigInteger(nonce);
		} catch(NumberFormatException e) {
			throw new IllegalArgumentException("Nonce value is NAN");
		}
		
		MasterSecret idxMasterSecret = 
				(MasterSecret) Parser.getInstance().parse(masterSecret);
		ProofSpec idxProofSpec = 
				(ProofSpec) Parser.getInstance().parse(proofSpec);
		
		HashMap<String, Credential> idxCredentials = 
				new HashMap<String, Credential>();
		for(String name : credentials.keySet()) {
			String credString = credentials.get(name);
			Credential idxCredential = 
					(Credential) Parser.getInstance().parse(credString);
			String tmpName = idxCredential.getCredStructId().toString().concat(
					Constants.DELIMITER).concat(name);
			idxCredentials.put(tmpName, idxCredential);
		}
		
		Prover prover = new Prover(idxMasterSecret, idxCredentials);
		Proof proof = prover.buildProof(idxNonce, idxProofSpec);
		
		String proofString = XMLSerializer.getInstance().serialize(proof);
		
		return proofString;
	}
	
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	
	private RoundZeroResponseData requestRound0(
			RoundZeroRequestData requestData) throws IOException{
		HttpPost httpPost = new HttpPost(issuerEndpoint);
		httpPost.addHeader("accept", "application/json");
		StringEntity requestEntity = 
				new StringEntity(gson.toJson(requestData));
		requestEntity.setContentType("application/json");
		httpPost.setEntity(requestEntity);
		
		HttpResponse response = httpClient.execute(httpPost);
		HttpEntity entity = response.getEntity();
		if(entity != null) {
			String responseString = IOUtils.toString(entity.getContent());
			return gson.fromJson(responseString, 
					RoundZeroResponseData.class);
		} else {
			throw new IOException("Unable to request round0");
		}
	}
	
	private RoundTwoResponseData requestRound2(String id,
			RoundTwoRequestData requestData) throws IOException{
		HttpPost httpPost = new HttpPost(issuerEndpoint + "/" + id);
		httpPost.addHeader("accept", "application/json");
		StringEntity requestEntity = 
				new StringEntity(gson.toJson(requestData));
		requestEntity.setContentType("application/json");
		httpPost.setEntity(requestEntity);
		
		HttpResponse response = httpClient.execute(httpPost);
		HttpEntity entity = response.getEntity();
		if(entity != null) {
			String responseString = IOUtils.toString(entity.getContent());
			return gson.fromJson(responseString, 
					RoundTwoResponseData.class);
		} else {
			throw new IOException("Unable to request round2");
		}
	}
	
	
	private StructureInformation requestStructureInformation() 
			throws IOException{
		HttpGet httpGet = new HttpGet(issuerEndpoint);
		HttpResponse response = httpClient.execute(httpGet);
		HttpEntity entity = response.getEntity();
		if(entity != null) {
			String responseString = IOUtils.toString(entity.getContent());
			return gson.fromJson(responseString, 
					StructureInformation.class);
		} else {
			throw new IOException("Unable to request structure information");
		}
		
	}
	
	private String requestCredentialStructure(String credentialName) 
		throws IllegalArgumentException, IOException{
		String csURL = 
				structureInformation.getCredentialStrucutures().get(
						credentialName);
		if(csURL == null)
			throw new IllegalArgumentException("Unknown credential structure");
		
		HttpGet httpGet = new HttpGet(
				structureInformation.getIssuerURL() + csURL);
		HttpResponse response = httpClient.execute(httpGet);
		HttpEntity entity = response.getEntity();
		if(entity != null) {
			String responseString = IOUtils.toString(entity.getContent());
			return responseString;
		} else {
			throw new IOException("Unable to request credential struc");
		}
		
	}
	
	private IssuanceSpec getIssuanceSpec(String credentialName) {
		try {
			URI pubKeyURI = new URI(structureInformation.getIssuerURL() 
					+ structureInformation.getPublicKeyURI());
			URI csUri = new URI(structureInformation.getIssuerURL() + 
					structureInformation.getCredentialStrucutures().get(
							credentialName));
			
			IssuanceSpec issuanceSpec = new IssuanceSpec(pubKeyURI, csUri);
			return issuanceSpec;
		} catch(URISyntaxException e) {
			throw new IllegalStateException(
					"Unable to construct issuance spec");
		}

	}
}