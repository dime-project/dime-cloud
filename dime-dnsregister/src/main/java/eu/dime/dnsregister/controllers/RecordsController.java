package eu.dime.dnsregister.controllers;

import eu.dime.dnsregister.entities.Records;
import java.io.UnsupportedEncodingException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.roo.addon.web.mvc.controller.json.RooWebJson;
import org.springframework.roo.addon.web.mvc.controller.scaffold.RooWebScaffold;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriUtils;
import org.springframework.web.util.WebUtils;

@RequestMapping("/recordses")
@Controller
@RooWebScaffold(path = "recordses", formBackingObject = Records.class)
@RooWebJson(jsonObject = Records.class)
public class RecordsController {

    @RequestMapping(value = "/{id}", headers = "Accept=application/json")
    @ResponseBody
    public ResponseEntity<String> showJson(@PathVariable("id") Integer id) {
	Records records = Records.findRecords(id);
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json; charset=utf-8");
	if (records == null) {
	    return new ResponseEntity<String>(headers, HttpStatus.NOT_FOUND);
	}
	return new ResponseEntity<String>(records.toJson(), headers, HttpStatus.OK);
    }
    
    @RequestMapping(value = "/findbyip", headers = "Accept=application/json")
    @ResponseBody
    public ResponseEntity<String> showJson(
	    @RequestParam(required = true) String ip) {
	
	Records records = null;
	try{
	records=Records.findRecordsesByContentEquals(ip).getSingleResult();
	
	}catch (Exception e){
		System.out.println ("Obviament la excepcio l'has creat tu ["+Records.findRecordsesByContentEquals(ip));
	}
	
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json; charset=utf-8");
	if (records == null) {
	    return new ResponseEntity<String>(headers, HttpStatus.NOT_FOUND);
	}
	
	return new ResponseEntity<String>("{\"publickey\":\""+records.getPublickey()+"\"}", headers, HttpStatus.OK);
	
	
    } 

    @RequestMapping(method = RequestMethod.POST, headers = "Accept=application/json")
    public ResponseEntity<String> createFromJson(@RequestBody String json) {

	HttpHeaders headers = new HttpHeaders();

	try {

	    // Obtain Data from JSON
	    Records records = Records.fromJsonToRecords(json);

           
	    String[] url = records.getName().split("\\.");
	    
	    String search= url[url.length-1];
	    int subdominis=0;
	    for(int i=url.length-2;i>=0;i--){
	    	switch (subdominis){
	    	case 0:
	        //buscar a la taula domains - provisional hard coded
	    		if (search.equals("dns.dime-project.eu")){
	    			//Search domainId in table domains - provisional hard coded
	    			records.setDomainId(1);
	    			//saltar a construir ordername
	    			subdominis=1;
	    			search=url[i];
	    		}
	    		else
	    			search=url[i]+"."+search;
	    		break;
	    	case 1:
	    		search=search+" "+url[i];
	    		break;
	    	}
	     }
	    
	    records.setOrdername(search);
	    records.setType("A");
	    records.setPrio(null);
	    records.setAuth(true);

	    // Save Data
	    records.persist();

	} catch (Exception e) {
	    headers.add("Content-Type", "text/plain");
	    return new ResponseEntity<String>("No correct JSON: [" + e.getMessage() + "]", headers, HttpStatus.BAD_REQUEST);
	}

	headers.add("Content-Type", "text/plain");
	return new ResponseEntity<String>("Created OK", headers, HttpStatus.CREATED);

    }

    @RequestMapping(headers = "Accept=application/json")
    @ResponseBody
    public ResponseEntity<String> listJson() {
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json; charset=utf-8");
	List<Records> result = Records.findAllRecordses();
	return new ResponseEntity<String>(Records.toJsonArray(result), headers, HttpStatus.OK);
    }

    @RequestMapping(value = "/jsonArray", method = RequestMethod.POST, headers = "Accept=application/json")
    public ResponseEntity<String> createFromJsonArray(@RequestBody String json) {
	for (Records records : Records.fromJsonArrayToRecordses(json)) {
	    records.persist();
	}
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json");
	return new ResponseEntity<String>(headers, HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.PUT, headers = "Accept=application/json")
    public ResponseEntity<String> updateFromJson(@RequestBody String json) {
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json");
	Records records = Records.fromJsonToRecords(json);
	if (records.merge() == null) {
	    return new ResponseEntity<String>(headers, HttpStatus.NOT_FOUND);
	}
	return new ResponseEntity<String>(headers, HttpStatus.OK);
    }

    @RequestMapping(value = "/jsonArray", method = RequestMethod.PUT, headers = "Accept=application/json")
    public ResponseEntity<String> updateFromJsonArray(@RequestBody String json) {
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json");
	for (Records records : Records.fromJsonArrayToRecordses(json)) {
	    if (records.merge() == null) {
		return new ResponseEntity<String>(headers, HttpStatus.NOT_FOUND);
	    }
	}
	return new ResponseEntity<String>(headers, HttpStatus.OK);
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE, headers = "Accept=application/json")
    public ResponseEntity<String> deleteFromJson(@PathVariable("id") Integer id) {
	Records records = Records.findRecords(id);
	HttpHeaders headers = new HttpHeaders();
	headers.add("Content-Type", "application/json");
	if (records == null) {
	    return new ResponseEntity<String>(headers, HttpStatus.NOT_FOUND);
	}
	records.remove();
	return new ResponseEntity<String>(headers, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.POST, produces = "text/html")
    public String create(@Valid Records records, BindingResult bindingResult, Model uiModel, HttpServletRequest httpServletRequest) {
	if (bindingResult.hasErrors()) {
	    populateEditForm(uiModel, records);
	    return "recordses/create";
	}
	uiModel.asMap().clear();
	records.persist();
	return "redirect:/recordses/" + encodeUrlPathSegment(records.getId().toString(), httpServletRequest);
    }

    @RequestMapping(params = "form", produces = "text/html")
    public String createForm(Model uiModel) {
	populateEditForm(uiModel, new Records());
	return "recordses/create";
    }

    @RequestMapping(value = "/{id}", produces = "text/html")
    public String show(@PathVariable("id") Integer id, Model uiModel) {
	uiModel.addAttribute("records", Records.findRecords(id));
	uiModel.addAttribute("itemId", id);
	return "recordses/show";
    }

    @RequestMapping(produces = "text/html")
    public String list(@RequestParam(value = "page", required = false) Integer page, @RequestParam(value = "size", required = false) Integer size, Model uiModel) {
	if (page != null || size != null) {
	    int sizeNo = size == null ? 10 : size.intValue();
	    final int firstResult = page == null ? 0 : (page.intValue() - 1) * sizeNo;
	    uiModel.addAttribute("recordses", Records.findRecordsEntries(firstResult, sizeNo));
	    float nrOfPages = (float) Records.countRecordses() / sizeNo;
	    uiModel.addAttribute("maxPages", (int) ((nrOfPages > (int) nrOfPages || nrOfPages == 0.0) ? nrOfPages + 1 : nrOfPages));
	} else {
	    uiModel.addAttribute("recordses", Records.findAllRecordses());
	}
	return "recordses/list";
    }

    @RequestMapping(method = RequestMethod.PUT, produces = "text/html")
    public String update(@Valid Records records, BindingResult bindingResult, Model uiModel, HttpServletRequest httpServletRequest) {
	if (bindingResult.hasErrors()) {
	    populateEditForm(uiModel, records);
	    return "recordses/update";
	}
	uiModel.asMap().clear();
	records.merge();
	return "redirect:/recordses/" + encodeUrlPathSegment(records.getId().toString(), httpServletRequest);
    }

    @RequestMapping(value = "/{id}", params = "form", produces = "text/html")
    public String updateForm(@PathVariable("id") Integer id, Model uiModel) {
	populateEditForm(uiModel, Records.findRecords(id));
	return "recordses/update";
    }

    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE, produces = "text/html")
    public String delete(@PathVariable("id") Integer id, @RequestParam(value = "page", required = false) Integer page, @RequestParam(value = "size", required = false) Integer size, Model uiModel) {
	Records records = Records.findRecords(id);
	records.remove();
	uiModel.asMap().clear();
	uiModel.addAttribute("page", (page == null) ? "1" : page.toString());
	uiModel.addAttribute("size", (size == null) ? "10" : size.toString());
	return "redirect:/recordses";
    }

    void populateEditForm(Model uiModel, Records records) {
	uiModel.addAttribute("records", records);
    }

    String encodeUrlPathSegment(String pathSegment, HttpServletRequest httpServletRequest) {
	String enc = httpServletRequest.getCharacterEncoding();
	if (enc == null) {
	    enc = WebUtils.DEFAULT_CHARACTER_ENCODING;
	}
	try {
	    pathSegment = UriUtils.encodePathSegment(pathSegment, enc);
	} catch (UnsupportedEncodingException uee) {
	}
	return pathSegment;
    }
}
