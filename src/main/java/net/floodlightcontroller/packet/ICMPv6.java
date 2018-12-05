package net.floodlightcontroller.packet;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.types.IPv6Address;

/**
 * 
 * @author Yu Zhou (yuz.thu@gmail.com)
 */
public class ICMPv6 extends BasePacket {

	protected byte icmpv6Type;
	protected byte icmpv6Code;
	protected short checksum;
	protected List<ICMPv6Option> options = null;
	//NA
	protected boolean routerFlag;
	protected boolean solicitedFlag;
	protected boolean overrideFlag;
	//RA
	protected byte curHopLimit;
	protected boolean managedAddressConfiguration;
	protected boolean otherConfiguration;
	protected short routerLifetime;
	protected int reachableTime;
	protected int retransTime;
	//NS NA
	protected IPv6Address targetAddress;
	
	protected byte[] cache;
	
	protected static final Map<Byte, Integer> paddingMap;
	
	private static final byte ROUTER_FLAG_MASK   = (byte)0x80;
	private static final byte SOLIITED_FLAG_MASK = (byte)0x40;
	private static final byte OVERRIDE_FLAG_MASK = (byte)0x20;
	
	public static final byte DESTINATION_UNREACHABLE = 1;
	public static final byte PACKET_TOO_BIG = 2;
	public static final byte TIME_EXCEEDED = 3;
	public static final byte PARAMETER_PROBLEM = 4;
	public static final byte ECHO_REQUEST = (byte)128;
	public static final byte ECHO_REPLY = (byte)129;
	public static final byte MULTICAST_LISTENER_QUERY = (byte)130; 
	public static final byte MULTICAST_LISTENER_REPORT = (byte)131; 
	public static final byte MULTICAST_LISTENER_DONE = (byte)132; 
	public static final byte ROUTER_SOLICITATION = (byte)133;
	public static final byte ROUTER_ADVERTSEMENT = (byte)134;
	public static final byte NEIGHBOR_SOLICITATION = (byte)135;
	public static final byte NEIGHBOR_ADVERTISEMENT = (byte)136;
	
	static{
		paddingMap = new HashMap<Byte,Integer>();
		paddingMap.put(DESTINATION_UNREACHABLE, 0x4);
		paddingMap.put(PACKET_TOO_BIG, 0x4);
		paddingMap.put(TIME_EXCEEDED, 0x4);
		paddingMap.put(PARAMETER_PROBLEM, 0x4);
		paddingMap.put(ECHO_REQUEST, 0x4);
		paddingMap.put(ECHO_REPLY, 0x4);
		paddingMap.put(MULTICAST_LISTENER_QUERY, 0x4);
		paddingMap.put(MULTICAST_LISTENER_REPORT, 0x4);
		paddingMap.put(MULTICAST_LISTENER_DONE, 0x4);
		paddingMap.put(ROUTER_ADVERTSEMENT, 0x4);
		paddingMap.put(ROUTER_SOLICITATION, 0x4);
		paddingMap.put(NEIGHBOR_ADVERTISEMENT, 0x4);
		paddingMap.put(NEIGHBOR_SOLICITATION, 0x4);
		
	}
	
	

	public byte getICMPv6Type() {
		return icmpv6Type;
	}
	public void setICMPv6Type(byte icmpv6Type) {
		this.icmpv6Type = icmpv6Type;
	}
	public byte getICMPv6Code() {
		return icmpv6Code;
	}
	public void setICMPv6Code(byte icmpv6Code) {
		this.icmpv6Code = icmpv6Code;
	}
	public short getChecksum() {
		return checksum;
	}
	public void setChecksum(short checksum) {
		this.checksum = checksum;
	}
	public List<ICMPv6Option> getOptions() {
		return options;
	}
	public void setOptions(List<ICMPv6Option> options) {
		this.options = options;
	}
	public boolean isRouterFlag() {
		return routerFlag;
	}
	public void setRouterFlag(boolean routerFlag) {
		this.routerFlag = routerFlag;
	}
	public boolean isSolicitedFlag() {
		return solicitedFlag;
	}
	public void setSolicitedFlag(boolean solicitedFlag) {
		this.solicitedFlag = solicitedFlag;
	}
	public boolean isOverrideFlag() {
		return overrideFlag;
	}
	public void setOverrideFlag(boolean overrideFlag) {
		this.overrideFlag = overrideFlag;
	}
	public byte getCurHopLimit() {
		return curHopLimit;
	}
	public void setCurHopLimit(byte curHopLimit) {
		this.curHopLimit = curHopLimit;
	}
	public boolean isManagedAddressConfiguration() {
		return managedAddressConfiguration;
	}
	public void setManagedAddressConfiguration(boolean managedAddressConfiguration) {
		this.managedAddressConfiguration = managedAddressConfiguration;
	}
	public boolean isOtherConfiguration() {
		return otherConfiguration;
	}
	public void setOtherConfiguration(boolean otherConfiguration) {
		this.otherConfiguration = otherConfiguration;
	}
	public short getRouterLifetime() {
		return routerLifetime;
	}
	public void setRouterLifetime(short routerLifetime) {
		this.routerLifetime = routerLifetime;
	}
	public int getReachableTime() {
		return reachableTime;
	}
	public void setReachableTime(int reachableTime) {
		this.reachableTime = reachableTime;
	}
	public int getRetransTime() {
		return retransTime;
	}
	public void setRetransTime(int retransTime) {
		this.retransTime = retransTime;
	}
	public IPv6Address getTargetAddress() {
		return targetAddress;
	}
	public void setTargetAddress(IPv6Address targetAddress) {
		this.targetAddress = targetAddress;
	}
	
	@Override
	public int hashCode() {
        final int prime = 5807;
        int result = super.hashCode();
        result = prime * result + icmpv6Type;
        result = prime * result + icmpv6Code;
        result = prime * result + checksum;
        return result;
	}
	@Override
	public byte[] serialize() {
		
		if(icmpv6Type!=ROUTER_SOLICITATION&&icmpv6Type!=ROUTER_ADVERTSEMENT
				&&icmpv6Type!=NEIGHBOR_SOLICITATION&&icmpv6Type!=NEIGHBOR_ADVERTISEMENT)
			return cache;
		
		int length = 4;
		if(paddingMap.containsKey(this.icmpv6Type)){
			length += 4;
		}
		if(icmpv6Type == NEIGHBOR_SOLICITATION
				||icmpv6Type == NEIGHBOR_ADVERTISEMENT){
			length += 16;	//targetAddress
		}else if(icmpv6Type == ROUTER_ADVERTSEMENT) {
			length*=2;
		}
		for(ICMPv6Option option:options){
			length += (int)option.getLength()*8;
//			System.out.println(Arrays.toString(option.getData())+"@@@@@@@@@@@@@@@@@@@@@@@@"+option.getLength());
		}
		
		byte[] data = new byte[length];
		ByteBuffer bb = ByteBuffer.wrap(data);
		bb.put(this.icmpv6Type);
		bb.put(this.icmpv6Code);
		bb.putShort(this.checksum);
		if(icmpv6Type==ROUTER_SOLICITATION||icmpv6Type==NEIGHBOR_SOLICITATION) {
			for(int i =0;i<4;i++) bb.put((byte)0);
			bb.put(targetAddress.getBytes());
		}else if(icmpv6Type==ROUTER_ADVERTSEMENT) {
			bb.put(curHopLimit);
			byte flag=0;
			if(managedAddressConfiguration) flag+=128;
			if(otherConfiguration) flag+=64;
			bb.put(flag);
			bb.putShort(routerLifetime);
			bb.putInt(reachableTime);
			bb.putInt(retransTime);
		}else if(icmpv6Type==NEIGHBOR_ADVERTISEMENT) {
			int flag=0;
			if(routerFlag) flag+=1<<31;
			if(solicitedFlag) flag+=1<<30;
			if(routerFlag) flag+=1<<29;
			bb.putInt(flag);
		}
		
		for(ICMPv6Option option : options) bb.put(option.getData());
		return data;
	}
	
	@Override
	public IPacket deserialize(byte[] data, int offset, int length) throws PacketParsingException {
		cache = new byte[length];	
		for(int i=0;i<length;i++){
			cache[i] = data[offset+i];
		}
		
		ByteBuffer bb = ByteBuffer.wrap(cache);
		icmpv6Type = bb.get();
		icmpv6Code = bb.get();
		checksum = bb.getShort();
		if(icmpv6Type!=ROUTER_SOLICITATION&&icmpv6Type!=ROUTER_ADVERTSEMENT
				&&icmpv6Type!=NEIGHBOR_SOLICITATION&&icmpv6Type!=NEIGHBOR_ADVERTISEMENT)
			return this;
		
		if(icmpv6Type==ROUTER_SOLICITATION) bb.getInt();
		else if(icmpv6Type==ROUTER_ADVERTSEMENT) {
			curHopLimit=bb.get();
			byte tmp=bb.get();
			managedAddressConfiguration=(tmp&128)==1;
			otherConfiguration=(tmp&64)==1;
			routerLifetime=bb.getShort();
			reachableTime=bb.getInt();
			retransTime=bb.getInt();
		}else if(icmpv6Type==NEIGHBOR_SOLICITATION) {
			bb.getInt();
			byte[] ipv6Address=new byte[16];
			for(int i=0;i<16;i++) ipv6Address[i]=bb.get();
			targetAddress=IPv6Address.of(ipv6Address);
		}else if(icmpv6Type==NEIGHBOR_ADVERTISEMENT) {
			int tmp=bb.getInt();
			tmp=tmp>>29;
			routerFlag=(tmp&4)==1;
			solicitedFlag=(tmp&2)==1;
			overrideFlag=(tmp&1)==1;
			byte[] ipv6Address=new byte[16];
			for(int i=0;i<16;i++) ipv6Address[i]=bb.get();
			targetAddress=IPv6Address.of(ipv6Address);
		}
		
		options=ICMPv6Option.getOptions(cache, bb.position());
		return this;
	}
}
