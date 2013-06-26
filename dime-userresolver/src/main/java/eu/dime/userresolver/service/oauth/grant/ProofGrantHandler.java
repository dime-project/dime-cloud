package eu.dime.userresolver.service.oauth.grant;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.grants.AbstractGrantHandler;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;

public class ProofGrantHandler extends AbstractGrantHandler {

	protected ProofGrantHandler(String grant, boolean isClientConfidential) {
		super(grant, isClientConfidential);
	}

	@Override
	public ServerAccessToken createAccessToken(Client client,
			MultivaluedMap<String, String> params) throws OAuthServiceException {
		
		return null;
	}

}
