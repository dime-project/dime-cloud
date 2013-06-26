// WARNING: DO NOT EDIT THIS FILE. THIS FILE IS MANAGED BY SPRING ROO.
// You may push code into the target .java compilation unit if you wish to edit any member(s).

package eu.dime.dnsregister.entities;

import eu.dime.dnsregister.entities.Records;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.transaction.annotation.Transactional;

privileged aspect Records_Roo_Jpa_ActiveRecord {
    
    @PersistenceContext
    transient EntityManager Records.entityManager;
    
    public static final EntityManager Records.entityManager() {
        EntityManager em = new Records().entityManager;
        if (em == null) throw new IllegalStateException("Entity manager has not been injected (is the Spring Aspects JAR configured as an AJC/AJDT aspects library?)");
        return em;
    }
    
    public static long Records.countRecordses() {
        return entityManager().createQuery("SELECT COUNT(o) FROM Records o", Long.class).getSingleResult();
    }
    
    public static List<Records> Records.findAllRecordses() {
        return entityManager().createQuery("SELECT o FROM Records o", Records.class).getResultList();
    }
    
    public static Records Records.findRecords(Integer id) {
        if (id == null) return null;
        return entityManager().find(Records.class, id);
    }
    
    public static List<Records> Records.findRecordsEntries(int firstResult, int maxResults) {
        return entityManager().createQuery("SELECT o FROM Records o", Records.class).setFirstResult(firstResult).setMaxResults(maxResults).getResultList();
    }
    
    @Transactional
    public void Records.persist() {
        if (this.entityManager == null) this.entityManager = entityManager();
        this.entityManager.persist(this);
    }
    
    @Transactional
    public void Records.remove() {
        if (this.entityManager == null) this.entityManager = entityManager();
        if (this.entityManager.contains(this)) {
            this.entityManager.remove(this);
        } else {
            Records attached = Records.findRecords(this.id);
            this.entityManager.remove(attached);
        }
    }
    
    @Transactional
    public void Records.flush() {
        if (this.entityManager == null) this.entityManager = entityManager();
        this.entityManager.flush();
    }
    
    @Transactional
    public void Records.clear() {
        if (this.entityManager == null) this.entityManager = entityManager();
        this.entityManager.clear();
    }
    
    @Transactional
    public Records Records.merge() {
        if (this.entityManager == null) this.entityManager = entityManager();
        Records merged = this.entityManager.merge(this);
        this.entityManager.flush();
        return merged;
    }
    
}