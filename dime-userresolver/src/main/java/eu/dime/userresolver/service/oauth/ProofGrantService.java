package eu.dime.userresolver.service.oauth;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;
import org.apache.cxf.rs.security.oauth2.common.AccessTokenRegistration;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ClientAccessToken;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.services.AbstractOAuthService;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.zurich.idmx.showproof.Proof;
import com.ibm.zurich.idmx.showproof.ProofSpec;
import com.ibm.zurich.idmx.showproof.Verifier;
import com.ibm.zurich.idmx.utils.Parser;

@Path("/authorize")
public class ProofGrantService extends AbstractOAuthService {
	
	private class AuthorizationResponse {
		public String id;
		public String nonce;
		public String proofSpec;
	}
	
	private class ProofResponse {
		public String token;
	}
	
	private class ErrorResponse {
		private String error;
	}
	
	private class AuthorisationRequest {
		public BigInteger nonce;
		public Client client;
		List<String> requestedScope;
		
		public String proofSpec;
	}
	
	////////////////////////////////////////////////////////////////////////////
	
	private static final Logger LOG = 
			LoggerFactory.getLogger(ProofGrantService.class);
	
	//Used to calculate nonce and session id
	//Should be the same value as in the SP ??
	private final int CL_MESSAGE_LENGTH = 256;
	private SecureRandom random;
	
	public static final String PROOF_GRANT = "proof_grant";
	
	private String supportedResponseType;
    private String supportedGrantType;
    private boolean isClientConfidential;
    
    private Map<String, AuthorisationRequest> requests = 
    		new ConcurrentHashMap<String, AuthorisationRequest>();
	
	public ProofGrantService() {
		supportedGrantType = PROOF_GRANT;
		supportedResponseType = OAuthConstants.TOKEN_RESPONSE_TYPE;
		isClientConfidential = false;
		
		try{
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch(NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to instantiate SHA1PRNG", e);
		}
	}
	
	@POST
    @Produces({"application/json" })
    public Response authorize(@FormParam("scope") String scope) {
		LOG.info("New authorization request");
		
        MultivaluedMap<String, String> params = getQueryParameters();
     	params.add("scope", scope);
        
        return startAuthorization(params);
    }
	
	@POST
	@Path("/{id}")
	@Produces("application/json")
	public Response proof(@PathParam("id") String id, 
			@FormParam("proof") String proof) {
		LOG.info("New proof for id: {} proof:{}", id, proof);
		
		if(proof == null)
			reportInvalidRequestError("No proof provied");
		if(id == null)
			reportInvalidRequestError("No id provided");
		
		MultivaluedMap<String, String> params = getQueryParameters();
		params.add("id", id);
		params.add("proof", proof);
		return completeAuthorization(params);
	}
	
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	
	private Response startAuthorization(
			MultivaluedMap<String, String> params) {
		Client client = getClient(UUID.randomUUID().toString());//TODO randomness
		
		List<String> requestedScope = 
        			OAuthUtils.parseScope(params.getFirst(OAuthConstants.SCOPE));
        try {
        	getDataProvider().convertScopeToPermissions(client, requestedScope);
        } catch(OAuthServiceException e) {
        	reportInvalidRequestError(e.getMessage());
        }
        
        String proofSpecString = "ERROR";
        try {
        	proofSpecString = IOUtils.toString(
        			ProofGrantService.class.getResourceAsStream(
        					"/proofspec/register-proofspec.xml"));
        } catch(IOException e) {
        	reportInvalidRequestError("Unable to load proof spec");//TOO: 500
        }
        
        String proofSpec = proofSpecString;
        BigInteger nonce = computeSymmetricRandom(CL_MESSAGE_LENGTH);
                        
        AuthorisationRequest authorisationRequest = new AuthorisationRequest();
        authorisationRequest.client = client;
        authorisationRequest.requestedScope = requestedScope;
        authorisationRequest.nonce = nonce;
        authorisationRequest.proofSpec = proofSpec;
        requests.put(client.getClientId(), authorisationRequest);
        
		AuthorizationResponse authorizationResponse = 
				new AuthorizationResponse();
		authorizationResponse.proofSpec = proofSpec;
		authorizationResponse.nonce = nonce.toString();
		authorizationResponse.id = client.getClientId();
        
		return Response.ok(authorizationResponse).build();
	}
	
	private Response completeAuthorization(
			MultivaluedMap<String, String> params) {
				
		AuthorisationRequest authorisationRequest = 
				requests.get(params.get("id").get(0));
		if(authorisationRequest == null) {
			reportInvalidRequestError("Unkown client id");
		}
		
		ProofSpec proofSpec = (ProofSpec) Parser.getInstance().parse(
				authorisationRequest.proofSpec);
		Proof proof = (Proof) Parser.getInstance().parse(
				params.getFirst("proof"));
		
		Verifier verifier = new Verifier(
				proofSpec, proof, authorisationRequest.nonce);
		if(!verifier.verify())
			reportInvalidRequestError("Unvalid proof");
		
		AccessTokenRegistration accessTokenRegistration = 
				new AccessTokenRegistration();
		accessTokenRegistration.setClient(authorisationRequest.client);
		accessTokenRegistration.setRequestedScope(
				authorisationRequest.requestedScope);
		accessTokenRegistration.setSubject(null);
		accessTokenRegistration.setGrantType(PROOF_GRANT);
		
		ServerAccessToken serverAccessToken = 
				getDataProvider().createAccessToken(accessTokenRegistration);
		ClientAccessToken clientToken = new ClientAccessToken(
				serverAccessToken.getTokenType(),
                serverAccessToken.getTokenKey());
				
		return Response.ok(clientToken).build();
	}
	
	private BigInteger computeSymmetricRandom(int bitlength) {
        BigInteger tmpRandom = new BigInteger(bitlength, random);
        
        if (random.nextBoolean()) {
            return tmpRandom.negate();
        }
        
        return tmpRandom;
    }
	
}
