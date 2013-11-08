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

import javax.ws.rs.FormParam;

import org.codehaus.jackson.annotate.JsonIgnore;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "users")
public class User {
	
	@JsonIgnore
	@DatabaseField(generatedId = true)
	private int id;
	
	@JsonIgnore
	@DatabaseField
	private String key;
	
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
	
	public String getKey(){
		return this.key;
	}
	
	public void setKey(String key){
		this.key = key;
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
	
	public User(String said, String name, String surname, String nickname) {
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
