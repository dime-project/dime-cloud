package eu.dime.userresolver.service.user;

import java.util.List;

public interface UserProvider {
	public User register(User user);
	
	public List<User> search(String name, String surname, String nickname);
	public List<User> searchAll(String query);
	public List<User> searchAllLike(String query);
	
	public User getBySaid(String said);
	
	public User update(String said, String name, String surname, String nickname);
	
	public User remove(String said);

}
