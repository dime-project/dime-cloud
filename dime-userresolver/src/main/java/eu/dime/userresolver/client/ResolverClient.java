/*
* Copyright 2013 by the digital.me project (http:\\www.dime-project.eu).
*
* Licensed under the EUPL, Version 1.1 only (the "Licence");
* You may not use this work except in compliance with the Licence.
* You may obtain a copy of the Licence at:
*
* http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
*
* Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the Licence for the specific language governing permissions and limitations under the Licence.
*/

package eu.dime.userresolver.client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.dime.userresolver.client.utils.HttpUtils;

public class ResolverClient {
		
	public static final Logger LOG = 
			LoggerFactory.getLogger(ResolverClient.class);
	
	private HttpClient httpClient;
		
	private String authEndpoint;
	private String serviceEnpoint;
		
	public ResolverClient(String serviceEndpoint, String authEndpoint) {
		this.serviceEnpoint = serviceEndpoint;
		this.authEndpoint = authEndpoint;
				
		httpClient = HttpUtils.createHttpClient();
	}
	
	////////////////////////////////////////////////////////////////////////////
	
	public void searchAll(String token, String name) {
		HttpGet httpGet;
		try {
			URIBuilder builder = new URIBuilder(serviceEnpoint + "/search");
			builder.setParameter("like", name);
			httpGet = new HttpGet(builder.build());	
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
		
		httpGet.setHeader("Authorization", "Bearer " + token);
		try {
			HttpResponse response = httpClient.execute(httpGet);
			HttpEntity entity = response.getEntity();
			if(entity != null) {
				String jsonResponse = IOUtils.toString(entity.getContent());
				LOG.debug("Search response: {}", jsonResponse);
			}
		} catch(IOException e) {
			LOG.debug("Unable to search", e);	
		}
	}
	
	public void search(String token, String name, String surname, 
			String nickname) {
		
		HttpGet httpGet;
		try {
			URIBuilder builder = new URIBuilder(serviceEnpoint + "/search");
			if(name != null)
				builder.setParameter("name", name);
			if(surname != null)
				builder.setParameter("surname", surname);
			if(nickname != null)
				builder.setParameter("nickname", nickname);
			
			httpGet = new HttpGet(builder.build());			
		} catch(URISyntaxException e) {
			throw new RuntimeException(e);
		}
		
		httpGet.setHeader("Authorization", "Bearer " + token);
		try {
			HttpResponse response = httpClient.execute(httpGet);
			HttpEntity entity = response.getEntity();
			if(entity != null) {
				String jsonResponse = IOUtils.toString(entity.getContent());
				LOG.debug("Search response: {}", jsonResponse);
			}
		} catch(IOException e) {
			LOG.debug("Unable to search", e);	
		}
		
	}

	public String register(String token, String name, String surname,
			String nickname, String said) throws IOException{
		HttpPost httpPost = new HttpPost(serviceEnpoint + "/register");
		httpPost.setHeader("Authorization", "Bearer " + token);
		
		List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
		nameValuePairs.add(new BasicNameValuePair("name", name));
		nameValuePairs.add(new BasicNameValuePair("surname", surname));
		nameValuePairs.add(new BasicNameValuePair("nickname", nickname));
		nameValuePairs.add(new BasicNameValuePair("said", said));
		
		try {
			httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
		} catch(UnsupportedEncodingException e) {
			LOG.debug("Unable to set post prameters", e);
			throw new RuntimeException("Unable to set post prameters");
		}
		
		HttpResponse response = httpClient.execute(httpPost);
		HttpEntity entity = response.getEntity();
		if(entity != null) {
			String jsonResponse = IOUtils.toString(entity.getContent());
			LOG.debug("Register response: {}", jsonResponse);
			return jsonResponse;
		}
		throw new IOException("Unable to register");
		
	}
	
}
