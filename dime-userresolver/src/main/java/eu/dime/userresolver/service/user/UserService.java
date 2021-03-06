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

package eu.dime.userresolver.service.user;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Philipp Schwarte (schwarte@wiwi.uni-siegen.de)
 *
 */
@Path("/")
public class UserService {
	private static final Logger LOG = 
			LoggerFactory.getLogger(UserService.class);
		
	private class SearchResponse {
		@SuppressWarnings("unused")
		public String version = apiVersion;
		public List<User> result;
	}
	
	private class RegisterResponse {
		@SuppressWarnings("unused")
		public String version = apiVersion;
		public User result;
		public String key;
	}
	
	private class ErrorResponse {
		@SuppressWarnings("unused")
		public String version = apiVersion;
		
		@SuppressWarnings("unused")
		public String error;
		
		public ErrorResponse(String error) {
			this.error = error;
		}
	}
	
	private static final String apiVersion = "0.1";
	
	private UserProvider userProvider;
	
	public void setUserProvider(UserProvider userManager) {
		this.userProvider = userManager;
	}
	
	
	@GET
	@Produces ("application/json")
	public Response users() {
		SearchResponse userResponse = new SearchResponse();
		userResponse.result = userProvider.search(null, null, null);
		
		return Response.ok(userResponse).build();
	}
		
	/**
	 * 
	 * http://[url]/register?said=[said]&name=[name]&surname=[surname]&nickname=[nickname]
	 * 
	 * {
     *	version: "0.1",
     *	result:
     *   	{ name: "NAME,"
     *     	surname: "SURNAME",
     *     	nickname: "NICKNAME",
     *     	said: "SAID"
     *   	}
	 *	}
	 * 
	 */
	@POST
	@Path("/register")
	@Consumes("application/x-www-form-urlencoded")
	@Produces ("application/json")
	public Response register(
			@FormParam("said") String said,
			@FormParam("name") String name,
			@FormParam("surname") String surname,
			@FormParam("nickname") String nickname) {
		
		LOG.info("Register user request: {} , {} , {} , {}", 
				new Object[]{said, name, surname, nickname});
		
		if(said.equals(""))
			return Response.ok(
					new ErrorResponse("Missing SAID")).status(400).build();
		
		User user = new User(said, name, surname, nickname);
		
		String key = RandomStringUtils.randomAlphanumeric(20);
		user.setKey(DigestUtils.sha256Hex(key));
	
		try {
			userProvider.register(user);
		} catch(IllegalArgumentException e) {
			return Response.ok(
					new ErrorResponse(e.getMessage())).status(400).build();
		}
		
		RegisterResponse response = new RegisterResponse();
		response.result = user;
		response.key = key;

		
		return Response.ok(response).build();		
	}
	
	
	/**
	 *  http://[url]/search?name=[name]&surname=[surname]&nickname=[nickname]
	 *  
	 *  {
     *		version: "0.1",
     *		result: [
     *   	{ 	name: "NAME",
     *     		surname: "SURNAME",
     *     		nickname: "NICKNAME",
     *     		said: "SAID"
     *   	},
     *  		{	name: "NAME",
     *     		surname: "SURNAME",
     *     		nickname: "NICKNAME",
     *     		said: "SAID"
     *   	},
     *   ...
     *		]
	 *	}
	 * 
	 * 
	 */
	@GET
	@Path("/search")
	@Produces ("application/json")
	public Response search(
			@QueryParam("like") String like,
			@QueryParam("string") String all,
			@QueryParam("name") String name,
			@QueryParam("surname") String surname,
			@QueryParam("nickname") String nickname) {
		
		SearchResponse response = new SearchResponse();
		
		if(like != null) {
			LOG.info("Catch all search request: {}", all);
			
			response.result = userProvider.searchAllLike(like);
		} else if(all != null) {
			LOG.info("Catch all search request: {}", all);
			
			response.result = userProvider.searchAll(all);
		} else {
			LOG.info("Search request: {} , {} , {}", 
				new Object[]{name, surname, nickname});
			
			response.result = userProvider.search(name, surname, nickname);
		}
		
		return Response.ok(response).build();
	}
	
	@POST
	@Path("/update")
	@Consumes("application/x-www-form-urlencoded")
	@Produces ("application/json")
	public Response update(
			@FormParam("said") String said,
			@FormParam("name") String name,
			@FormParam("surname") String surname,
			@FormParam("nickname") String nickname) {
		
		LOG.info("Update user request: {} , {} , {} , {}", 
				new Object[]{said, name, surname, nickname});
		
		if(said.equals(""))
			return Response.ok(
					new ErrorResponse("Missing SAID")).status(400).build();
		
		User user =  userProvider.update(said, name, surname, nickname);
		
		RegisterResponse response = new RegisterResponse();
		response.result = user;
		
		return Response.ok(response).build();		
	}
	
	@POST
	@Path("/remove")
	@Produces ("application/json")
	public Response remove(@QueryParam("said") String said) {
		try {
			RegisterResponse registerResponse = new RegisterResponse();
			
			User user = userProvider.remove(said);
			registerResponse.result = user;
			
			return Response.ok(registerResponse).build();			
		} catch (IllegalArgumentException e) {
			return Response.ok(new ErrorResponse(e.getMessage())).status(
					Response.Status.NOT_FOUND).build();
		} catch (IllegalStateException e) {
			return Response.ok(new ErrorResponse(e.getMessage())).status(
					Response.Status.INTERNAL_SERVER_ERROR).build();
		}
	}
	
	
	@DELETE
	@Produces ("application/json")
	public Response remove2(@QueryParam("said") String said) {
		try {
			RegisterResponse registerResponse = new RegisterResponse();
			
			User user = userProvider.remove(said);
			registerResponse.result = user;
			
			return Response.ok(registerResponse).build();			
		} catch (IllegalArgumentException e) {
			return Response.ok(new ErrorResponse(e.getMessage())).status(
					Response.Status.NOT_FOUND).build();
		} catch (IllegalStateException e) {
			return Response.ok(new ErrorResponse(e.getMessage())).status(
					Response.Status.INTERNAL_SERVER_ERROR).build();
		}
	}
	
}
