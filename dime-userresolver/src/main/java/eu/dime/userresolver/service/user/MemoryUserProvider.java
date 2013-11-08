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

import java.util.ArrayList;
import java.util.List;

public class MemoryUserProvider implements UserProvider{
	
	private int lastId = 0;
	private List<User> users = new ArrayList<User>();
	
	@Override
	public User register(User user) {
		
		if(search(user.getName(), user.getSurname(), user.getNickname()).size() 
				!= 0) {
			throw new IllegalArgumentException("Duplicate user");
		}
		
		user.setId(++lastId);
		users.add(user);
		
		return user;
	}  

	@Override
	public List<User> search(String name, String surname, String nickname) {
		List<User> results = new ArrayList<User>();
		
		for(User user : users) {
			if(
				name == null ? true : user.getName().equals(name)
				&&
				surname == null ? true : user.getSurname().equals(surname)
				&&
				nickname == null ? true : user.getNickname().equals(nickname)
			   ) {
				results.add(user);
			}
		}
		return results;
	}
	
	@Override
	public List<User> searchAll(String searchAll) {
		return null;
	}

	@Override
	public List<User> searchAllLike(String query) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public User remove(String said) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public User getBySaid(String said) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public User update(String said, String name, String surname, String nickname) {
		// TODO Auto-generated method stub
		return null;
	}

}
