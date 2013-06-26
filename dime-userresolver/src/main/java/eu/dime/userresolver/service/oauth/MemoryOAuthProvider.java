package eu.dime.userresolver.service.oauth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.cxf.rs.security.oauth2.common.AccessTokenRegistration;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeRegistration;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.bearer.BearerAccessToken;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oauth2.utils.OAuthUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MemoryOAuthProvider implements AuthorizationCodeDataProvider {
	private static final Logger LOG = 
			LoggerFactory.getLogger(MemoryOAuthProvider.class);
	
	private static Map<String, OAuthPermission> permissions = 
			new ConcurrentHashMap<String, OAuthPermission>();
	
	static {
		OAuthPermission permission = 
				new OAuthPermission("search", "Allows searching for users");
		permission.setHttpVerbs(Arrays.asList("GET"));
		permission.setUris(Arrays.asList("/*"));
		permissions.put(permission.getPermission(), permission);
		
		permission = 
				new OAuthPermission(
						"register", "Allows registration of new users");
		permission.setHttpVerbs(Arrays.asList("POST", "GET"));
		permission.setUris(Arrays.asList("/*"));
		permissions.put(permission.getPermission(), permission);
	}
	
	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	
	private Map<String, Client> clients = 
			new ConcurrentHashMap<String, Client>();
	
	private Map<String, ServerAccessToken> accessTokens = 
			new ConcurrentHashMap<String, ServerAccessToken>();
	
	private Map<String, ServerAuthorizationCodeGrant> authTokens = 
			new ConcurrentHashMap<String, ServerAuthorizationCodeGrant>();
	
	////////////////////////////////////////////////////////////////////////////
	
	@Override
	public Client getClient(String clientId) throws OAuthServiceException {
		LOG.debug("Request client for id: {}", clientId);
		
		Client client = clients.get(clientId);
		if(client != null)
			return client;
		
		client = new Client(clientId, null, false);
		clients.put(clientId, client);
		return client;
	}
	
	@Override
	public List<OAuthPermission> convertScopeToPermissions(Client client,
			List<String> requestedScopes) throws OAuthServiceException {
		LOG.debug("Requesting permissons for scope: {}", requestedScopes);
		
		if(requestedScopes.isEmpty())
			throw new OAuthServiceException("No scope provided");
		
		List<OAuthPermission> permissions = new ArrayList<OAuthPermission>();
		
		for(String scope : requestedScopes) {
			OAuthPermission permission = 
					MemoryOAuthProvider.permissions.get(scope);
			if(permission != null)
				permissions.add(permission);
			else
				throw new OAuthServiceException("Unknown scope");
		}
		
		return permissions;
	}
	
	////////////////////////////////////////////////////////////////////////////

	@Override
	public ServerAccessToken createAccessToken(
			AccessTokenRegistration tokenRegistration)
					throws OAuthServiceException {
		
		ServerAccessToken accessToken = 
				new BearerAccessToken(tokenRegistration.getClient(), 3600l);
		
		List<String> scope = tokenRegistration.getApprovedScope().isEmpty() ?
				tokenRegistration.getRequestedScope() :
				tokenRegistration.getApprovedScope();
		
		accessToken.setScopes(convertScopeToPermissions(
				tokenRegistration.getClient(), scope));
		accessToken.setSubject(tokenRegistration.getSubject());
		accessToken.setGrantType(tokenRegistration.getGrantType());
		
		accessTokens.put(accessToken.getTokenKey(), accessToken);
		
		return accessToken;
	}

	@Override
	public ServerAccessToken getAccessToken(String tokenKey)
			throws OAuthServiceException {
		ServerAccessToken accessToken = accessTokens.get(tokenKey);
		if(accessToken != null)
			return accessToken;
		throw new OAuthServiceException("Unknown access token");
	}
	
	@Override
	public void removeAccessToken(ServerAccessToken serverAccessToken)
			throws OAuthServiceException {
		if(accessTokens.remove(serverAccessToken.getTokenKey()) == null)
			throw new OAuthServiceException("Unknown access token");
	}

	////////////////////////////////////////////////////////////////////////////

	@Override
	public ServerAccessToken getPreauthorizedToken(Client arg0,
			UserSubject arg1, String arg2) throws OAuthServiceException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ServerAccessToken refreshAccessToken(String arg0, String arg1)
			throws OAuthServiceException {
		// TODO Auto-generated method stub
		return null;
	}

	

	////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////
	
	@Override
	public ServerAuthorizationCodeGrant createCodeGrant(
			AuthorizationCodeRegistration authRegistration) 
					throws OAuthServiceException {
		
		ServerAuthorizationCodeGrant codeGrant = 
				new ServerAuthorizationCodeGrant(
						authRegistration.getClient(), 60);
		authTokens.put(codeGrant.getCode(), codeGrant);
		
		return codeGrant;
	}

	@Override
	public ServerAuthorizationCodeGrant removeCodeGrant(String code)
			throws OAuthServiceException {
		
		return authTokens.get(code);
	}

}
