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

package eu.dime.dnsregister.controllers;

import eu.dime.dnsregister.entities.Records;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.format.support.FormattingConversionServiceFactoryBean;
import org.springframework.roo.addon.web.mvc.controller.converter.RooConversionService;

@Configurable
/**
 * A central place to register application converters and formatters. 
 */
@RooConversionService
public class ApplicationConversionServiceFactoryBean extends FormattingConversionServiceFactoryBean {

	@Override
	protected void installFormatters(FormatterRegistry registry) {
		super.installFormatters(registry);
		// Register application converters and formatters
	}

	public Converter<Records, String> getRecordsToStringConverter() {
        return new org.springframework.core.convert.converter.Converter<eu.dime.dnsregister.entities.Records, java.lang.String>() {
            public String convert(Records records) {
                return new StringBuilder().append(records.getDomainId()).append(" ").append(records.getName()).append(" ").append(records.getType()).append(" ").append(records.getContent()).toString();
            }
        };
    }

	public Converter<Integer, Records> getIdToRecordsConverter() {
        return new org.springframework.core.convert.converter.Converter<java.lang.Integer, eu.dime.dnsregister.entities.Records>() {
            public eu.dime.dnsregister.entities.Records convert(java.lang.Integer id) {
                return Records.findRecords(id);
            }
        };
    }

	public Converter<String, Records> getStringToRecordsConverter() {
        return new org.springframework.core.convert.converter.Converter<java.lang.String, eu.dime.dnsregister.entities.Records>() {
            public eu.dime.dnsregister.entities.Records convert(String id) {
                return getObject().convert(getObject().convert(id, Integer.class), Records.class);
            }
        };
    }

	public void installLabelConverters(FormatterRegistry registry) {
        registry.addConverter(getRecordsToStringConverter());
        registry.addConverter(getIdToRecordsConverter());
        registry.addConverter(getStringToRecordsConverter());
    }

	public void afterPropertiesSet() {
        super.afterPropertiesSet();
        installLabelConverters(getObject());
    }
}
