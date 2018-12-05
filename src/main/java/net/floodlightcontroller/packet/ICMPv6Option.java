package net.floodlightcontroller.packet;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Yu Zhou (yuz.thu@gmail.com)
 */
public class ICMPv6Option{
	
	protected byte code;
	protected byte length;
	protected byte[] data;
	
	public ICMPv6Option(byte code,byte length){
		this.code = code;
		this.length = length;
		this.data = new byte[length*8];
	}
	
	public byte getCode() {
		return code;
	}

	public void setCode(byte code) {
		this.code = code;
	}

	public byte getLength() {
		return length;
	}



	public void setLength(byte length) {
		this.length = length;
	}

	public byte[] getData() {
		return data;
	}



	public void setData(byte[] value) {
		this.data = value;
	}


	public byte[] serilize(){
		int k = 2;
		byte data[] = new byte[2 + length*8];
		data[0] = code;
		data[1] = length;
		
		for(byte i:data){
			data[k] = i;
		}
		return data;
	}

	public static ICMPv6Option getOption(byte[] data,int offset){
		ICMPv6Option option = new ICMPv6Option(data[offset],data[offset+1]);
		for(int i=0;i<option.length-2;i++){
			option.data[i] = data[i + offset + 2];
		}
		return option;
	}
	
	public static List<ICMPv6Option> getOptions(byte[] data,int offset){
		List<ICMPv6Option> options = new ArrayList<ICMPv6Option>();
		for(int n=offset;n<data.length;){
			ICMPv6Option option = getOption(data, n);
			n+=((int)option.length*8);
			options.add(option);
		}
		return options;
	}
}
