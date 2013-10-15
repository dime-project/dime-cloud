package eu.dime.userresolver.service.basicauth;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.cxf.binding.soap.interceptor.SoapHeaderInterceptor;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.ws.addressing.EndpointReferenceType;
import org.apache.log4j.Logger;

import eu.dime.userresolver.service.user.User;
import eu.dime.userresolver.service.user.UserProvider;
 
/**
 * 
 * @author marcel
 *
 */
public class BasicAuthenticationInterceptor extends SoapHeaderInterceptor {

    protected Logger log = Logger.getLogger(getClass());
        
	private UserProvider userProvider;
	
	public void setUserProvider(UserProvider userManager) {
		this.userProvider = userManager;
	}
    
    /**
     * org.apache.cxf.message.Message.PROTOCOL_HEADERS -- 
     * {Accept=[text/html,application/xhtml+xml,application/xml;q=0.9,image/webp, *;q=0.8], 
     * accept-encoding=[gzip,deflate,sdch], 
     * accept-language=[de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4], 
     * Authorization=[Basic Og==], 
     * cache-control=[max-age=0], 
     * connection=[keep-alive], 
     * Content-Type=[null], 
     * dnt=[1], 
     * host=[141.99.159.223], 
     * user-agent=[...]}
    */
    
    @Override 
    public void handleMessage(Message message) throws Fault {
        AuthorizationPolicy policy = message.get(AuthorizationPolicy.class);
        Set<Entry<String, Object>> set = message.entrySet();
        
        if (policy == null) {
            sendErrorResponse(message, HttpURLConnection.HTTP_UNAUTHORIZED);
            return;
        }
        String address;
        if (message != null && message.get(Message.ENDPOINT_ADDRESS) != null){
        	address = message.get(Message.ENDPOINT_ADDRESS).toString();
        } else {
        	address = "";
        }
        if (!address.endsWith("register")){
	        User user = userProvider.getBySaid(policy.getUserName());
	        String key = DigestUtils.sha256Hex(policy.getPassword());
	
	        if (!user.getKey().equals(key)) {
	            log.warn("Invalid username or password for user: " + policy.getUserName());
	            sendErrorResponse(message, HttpURLConnection.HTTP_FORBIDDEN);
	            return;
	        }
        }
    }
    
    private void sendErrorResponse(Message message, int responseCode) {
        Message outMessage = getOutMessage(message);
        outMessage.put(Message.RESPONSE_CODE, responseCode);
        
        // Set the response headers
        Map<String, List<String>> responseHeaders =
            (Map<String, List<String>>)message.get(Message.PROTOCOL_HEADERS);
        if (responseHeaders != null) {
            responseHeaders.put("WWW-Authenticate", Arrays.asList("Basic realm="));
            responseHeaders.put("Content-Length", Arrays.asList("0"));
        }
        message.getInterceptorChain().abort();
        try {
            getConduit(message).prepare(outMessage);
            close(outMessage);
        } catch (IOException e) {
            log.warn(e.getMessage(), e);
        }
    }
    
    private Message getOutMessage(Message inMessage) {
        Exchange exchange = inMessage.getExchange();
        Message outMessage = exchange.getOutMessage();
        if (outMessage == null) {
            Endpoint endpoint = exchange.get(Endpoint.class);
            outMessage = endpoint.getBinding().createMessage();
            exchange.setOutMessage(outMessage);
        }
        outMessage.putAll(inMessage);
        return outMessage;
    }
    
    private Conduit getConduit(Message inMessage) throws IOException {
        Exchange exchange = inMessage.getExchange();
        EndpointReferenceType target = exchange.get(EndpointReferenceType.class);
        Conduit conduit =
            exchange.getDestination().getBackChannel(inMessage, null, target);
        exchange.setConduit(conduit);
        return conduit;
    }
    
    private void close(Message outMessage) throws IOException {
        OutputStream os = outMessage.getContent(OutputStream.class);
        os.flush();
        os.close();
    }
}
