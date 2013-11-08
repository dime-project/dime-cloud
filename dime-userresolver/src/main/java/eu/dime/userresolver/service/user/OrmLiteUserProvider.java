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

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.stmt.PreparedQuery;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.stmt.Where;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

public class OrmLiteUserProvider implements UserProvider{
	private static final Logger LOG = 
			LoggerFactory.getLogger(OrmLiteUserProvider.class);
	
	private static final String PROPERTIES_URI = 
			"/application.properties";
	private Properties properties;
	
	private File appFolder;
	
	private ConnectionSource connectionSource;
	private Dao<User, Integer> userDao;
	
	public OrmLiteUserProvider() {
		properties = new Properties();
		try {
			properties.load(
					OrmLiteUserProvider.class.getResourceAsStream(
							PROPERTIES_URI));
			
			appFolder = new File(FilenameUtils.concat(
					FileUtils.getUserDirectoryPath(), 
					properties.getProperty("app.folder")));
			
			FileUtils.forceMkdir(appFolder);
		} catch(IOException e) {
			LOG.error("Unable to create app folder", e);
			throw new RuntimeException("Unable to load properties", e);
		}
		
		try {
			connectionSource = new JdbcConnectionSource("jdbc:sqlite:"
					+ FilenameUtils.concat(
							appFolder.getAbsolutePath(), "resolver.db"));
			
			userDao = DaoManager.createDao(connectionSource, User.class);
			
			// schema upgrade "hack"
			try {
				userDao.executeRaw("ALTER TABLE `users` ADD COLUMN key STRING;");
			} catch (SQLException e){
				LOG.info("Schema update failed. Already updated?");
			}
			
			TableUtils.createTableIfNotExists(connectionSource, User.class);
		} catch(SQLException e) {
			LOG.error("Unable to create database", e);
			throw new RuntimeException("Unable to create database", e);
		}
		
	}
	
	@Override
	public User register(User user) {
		try {
			PreparedQuery<User> query = 
					userDao.queryBuilder().where().eq(
							"said", user.getSaid()).prepare();
			
			if(userDao.query(query).size() == 0) {
				int id =userDao.create(user);
				return userDao.queryForId(id);
			}
						
			throw new IllegalArgumentException("User exists");
		} catch(SQLException e) {
			LOG.error("Unabe to create user", e);
			throw new IllegalArgumentException("Unabe to create user", e);
		}
	}
	
	@Override
	public List<User> searchAll(String searchAll) {
		try {
			QueryBuilder<User, Integer> queryBuilder = userDao.queryBuilder();
			queryBuilder.where().like("name", searchAll)
				.or().like("surname", searchAll)
				.or().like("nickname", searchAll);
			
			return queryBuilder.query();
		} catch(SQLException e) {
			return new ArrayList<User>();
		}
	}
	
	@Override
	public List<User> search(String name, String surname, String nickname) {
		try {
			//TODO better
			if(name == null && surname == null && nickname == null)
				return userDao.queryForAll();
			
			QueryBuilder<User, Integer> queryBuilder = userDao.queryBuilder();
			
			Where<User, Integer> where = queryBuilder.where();
			if(name != null && surname == null && nickname == null)
				where.eq("name", name);
			if(name == null && surname != null && nickname == null)
				where.eq("surname", surname);
			if(name == null && surname == null && nickname != null)	
				where.eq("nickname", nickname);
			
			if(name != null && surname != null && nickname == null)
				where.eq("name", name).and().eq("surname", surname);
			if(name != null && surname == null && nickname != null)
				where.eq("name", name).and().eq("nickname", nickname);
			
			if(name == null && surname != null && nickname != null)
				where.eq("surname", surname).and().eq("nickname", nickname);
			
			if(name != null && surname != null && nickname != null)
				where.eq("surname", surname).and().eq(
						"nickname", nickname).and().eq("name", name);
			
			return queryBuilder.query();
		} catch(SQLException e) {
			return new ArrayList<User>();
		}
	}
	
	@Override
	public User remove(String said) {
		try {
			LOG.info("Removing user with said -> {}", said);
			
			PreparedQuery<User> query = 
					userDao.queryBuilder().where().eq(
							"said", said).prepare();
			List<User> users = userDao.query(query);
			
			if(users.size() == 0) {
				LOG.info("No user with said -> {} in database", said);
				throw new IllegalArgumentException("Unknown said -> " + said);
			}
			
			userDao.delete(users.get(0));
			
			return users.get(0);
		} catch (SQLException e) {
			LOG.error("SQLException during user deletion", e);
			throw new IllegalStateException(
					"SQLException during user deletion - " + e.getMessage());
		}
	}
	
	@Override
	public List<User> searchAllLike(String query) {
		
		query = '%' + query + '%';
		
		try {
			QueryBuilder<User, Integer> queryBuilder = userDao.queryBuilder();
			queryBuilder.where().like("name", query)
				.or().like("surname", query)
				.or().like("nickname", query);
			
			return queryBuilder.query();
		} catch(SQLException e) {
			return new ArrayList<User>();
		}
	}

	@Override
	public User getBySaid(String said) {
		try {
			LOG.info("Searching user with said -> {}", said);
			
			PreparedQuery<User> query = 
					userDao.queryBuilder().where().eq(
							"said", said).prepare();
			List<User> users = userDao.query(query);
			
			
			if(users.size() == 0) {
				LOG.info("No user with said -> {} in database", said);
				throw new IllegalArgumentException("Unknown said -> " + said);
			}
						
			return users.get(0);
		} catch (SQLException e) {
			LOG.error("SQLException during user get", e);
			throw new IllegalStateException(
					"SQLException during user get - " + e.getMessage());
		}
	}
	
	@Override
	public User update(String said, String name, String surname, String nickname) {
		try {
			LOG.info("Searching user with said -> {}", said);
			
			PreparedQuery<User> query = 
					userDao.queryBuilder().where().eq(
							"said", said).prepare();
			List<User> users = userDao.query(query);
			
			
			if(users.size() == 0) {
				LOG.info("No user with said -> {} in database", said);
				throw new IllegalArgumentException("Unknown said -> " + said);
			}
						
			User user = users.get(0);
			user.setName(name);
			user.setSurname(surname);
			user.setNickname(nickname);
			userDao.update(user);
			return user;
		} catch (SQLException e) {
			LOG.error("SQLException during user get", e);
			throw new IllegalStateException(
					"SQLException during user get - " + e.getMessage());
		}
	}

}
