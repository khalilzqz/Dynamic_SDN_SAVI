package net.floodlightcontroller.savi.binding;

import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.devicemanager.SwitchPort;

public class Binding<T extends IPAddress<?>> {
	private BindingStatus status;
	
	private SwitchPort switchPort;
	private MacAddress macAddress;
	private T address;
	
	private long transactionId;
	private long bindingTime; 
	private long leaseTime;
	
	private static final int PRIME = 43;
	
	
	public Binding() {
		// TODO Auto-generated constructor stub
		this.switchPort = null;
		this.macAddress = null;
		this.address = null;
		this.transactionId = 0;
		this.bindingTime = 0;
		this.leaseTime = 0;
	}
	
	@Override
	public String toString(){
		
		return "{"+"dpid:"+switchPort.getSwitchDPID().toString()
				  +",port:"+switchPort.getPort().toString()
				  +",mac:"+macAddress.toString()
				  +",ip:"+address.toString()
				  +",id:"+transactionId
				  +",lease-time:"+leaseTime
				  +",binding-time:"+bindingTime
				  +"}";
	}
	
	public boolean check(MacAddress macAddress, T address){
		return this.macAddress.equals(macAddress)&&this.address.equals(address);
	}
	
	public boolean isLeaseExpired(){
		// leaseTime == 0 means lease never expires
		if(leaseTime == 0){
			return false;
		}
		long currentTime = System.currentTimeMillis() / 1000;
		if(currentTime>=(bindingTime+leaseTime)){
			return false;
		}
		else{
			return true;
		}
	}
	
	public void clearLeaseTime(){
		this.bindingTime = 0;
		this.leaseTime = 0;
	}
	
	@Override
	public int hashCode(){
		int result = 1;
		
		result = PRIME*result + ((address == null)?0:address.hashCode());
		result = PRIME*result + ((macAddress == null)?0:macAddress.hashCode());
		result = PRIME*result + ((switchPort == null)?0:switchPort.hashCode());
		
		return result;
	}
	
	public BindingStatus getStatus() {
		return status;
	}
	
	public void setStatus(BindingStatus status) {
		this.status = status;
	}
	
	public SwitchPort getSwitchPort() {
		return switchPort;
	}
	
	public void setSwitchPort(SwitchPort switchPort) {
		this.switchPort = switchPort;
	}
	
	public MacAddress getMacAddress() {
		return macAddress;
	}
	
	public void setMacAddress(MacAddress macAddress) {
		this.macAddress = macAddress;
	}
	
	public T getAddress() {
		return address;
	}
	
	public void setAddress(T address) {
		this.address = address;
	}
	
	public long getTransactionId() {
		return transactionId;
	}
	
	public void setTransactionId(long transactionId) {
		this.transactionId = transactionId;
	}
	
	public long getBindingTime() {
		return bindingTime;
	}
	
	public void setBindingTime() {
		this.bindingTime = System.currentTimeMillis() / 1000;
	}
	
	public long getLeaseTime() {
		return leaseTime;
	}
	
	public void setLeaseTime(long leaseTime) {
		this.leaseTime = leaseTime;
	}
	
	public boolean expirable(){
		return leaseTime == 0;
	}
}
