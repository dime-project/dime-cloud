package eu.dime.userresolver.service.user;

import javax.ws.rs.FormParam;

import org.codehaus.jackson.annotate.JsonIgnore;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "users")
public class User {
	
	@JsonIgnore
	@DatabaseField(generatedId = true)
	private int id;
	
	@DatabaseField
	private String surname;
	@DatabaseField
	private String name;
	@DatabaseField
	private String nickname;
	@DatabaseField
	private String said;
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	
	public String getSurname() {
		return surname;
	}
	public void setSurname(String surname) {
		this.surname = surname;
	}
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	public String getNickname() {
		return nickname;
	}
	public void setNickname(String nickname) {
		this.nickname = nickname;
	}
	
	public String getSaid() {
		return said;
	}
	public void setSaid(String said) {
		this.said = said;
	}
	
	public User() {}
	
	public User(String said, String name, String surname,	String nickname) {
		this.surname = surname;
		this.name = name;
		this.nickname = nickname;
		this.said = said;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", surname=" + surname + ", name=" + name
				+ ", nickname=" + nickname + ", said=" + said + "]";
	}

}
