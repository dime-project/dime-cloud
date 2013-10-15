package eu.dime.userresolver.client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.dime.userresolver.service.user.UserService;

public class TestApp {
	private static final Logger LOG = LoggerFactory.getLogger(TestApp.class);
	
	private static final String ISSUER_ENDPOINT = 
			"http://dime.itsec-siegen.info/issuer/api/issuer";
			//"http://localhost:8080/issuer/api/issuer";
	
	private static final String AUTH_ENDPOINT = 
			"http://dime.itsec-siegen.info/user-resolver/api/oauth";
			//"http://localhost:8080/user-resolver/api/oauth";
	
	private static final String RESOLVER_ENDPOINT = 
			"http://dime.itsec-siegen.info/user-resolver/api/users";
			//"http://localhost:8080/user-resolver/api/noauth/users";
	
	private static IdemixClient idemixClient;
	private static ResolverClient resolverClient;
	
	private static String masterSecret;
	private static String credential;
	
	private static String token;
	
	public static void main(String[] args) throws IOException {
		idemixClient = new IdemixClient(ISSUER_ENDPOINT);
		resolverClient = new ResolverClient(
				RESOLVER_ENDPOINT, AUTH_ENDPOINT, idemixClient);
		
		
		masterSecret = idemixClient.generateMasterSecret();
		
		String name = "foo";
		String surname = "bar";
		String nickname = "dsdsdss";
		String said = "F00B4R";
		
		Map<String, String> values = new HashMap<String, String>();
		values.put("name", "foo");
		values.put("surname", "foo");
		values.put("nickname", "foo");
		credential = 
				idemixClient.getCredential(
						masterSecret, "dime-credential", values);
		LOG.info("Credential: {}", credential);
		
		////////////////////////////////////////////////////////////////////////
		
		String scope = "register"; //defines proofSpec
		token = resolverClient.getToken(scope, masterSecret, credential);
		LOG.info("Token: {}", token); //OAuth2 Bearer token
		
		
		//403 if scope == search
//		resolverClient.register(token ,name, surname, nickname, said);
		//resolverClient.search(token, name, surname, nickname);
		//resolverClient.searchAll(token, "ophi");
		UserService userService = new UserService();
		Response resp = userService.register(said, name, surname, nickname);
		System.out.println(resp.getEntity().toString());
		
	}

}
