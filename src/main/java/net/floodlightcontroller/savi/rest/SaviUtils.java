package net.floodlightcontroller.savi.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class SaviUtils {
	private SaviUtils() {
		
	}
	
	/*
	 * 将json字符串，转成map
	 */
	public static Map<String, String> jsonToStringMap(String json){
		if(json==null||json.isEmpty()) return null;
		Map<String, String> jsonMap=new HashMap<>();
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp = null;

		try {
			try {
				jp = f.createParser(json);
			} catch (IOException e) {
				e.printStackTrace();
			}
			jp.nextToken();
			if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
				throw new IOException("Expected START_OBJECT");
			}

			while (jp.nextToken() != JsonToken.END_OBJECT) {
				if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
					throw new IOException("Expected FIELD_NAME");
				}

				String key = jp.getCurrentName().toLowerCase();
				jp.nextToken();
				jsonMap.put(key, jp.getText());
			}
		}
		catch (IOException e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return jsonMap;
	}
	
	/*
	 * 以“，”划分字符串，再以“=”划分字符串，最后返回一个map
	 * a=1,b=2转成map
	 */
	public static Map<String, String> splitToStringMap(String json){
		if(json==null||json.isEmpty()) return null;
		Map<String, String> map=new HashMap<>();
		String[] jsons=json.split(",");
		for(String temp:jsons){
			String[] splits=temp.split("=");
			map.put(splits[0], splits[1]);
		}
		return map;
	}
}
