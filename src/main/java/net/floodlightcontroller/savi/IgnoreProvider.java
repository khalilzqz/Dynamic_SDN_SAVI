package net.floodlightcontroller.savi;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;

public class IgnoreProvider extends ReactiveProvider {
	@Override
	protected RoutingAction process(SwitchPort switchPort, Ethernet eth) {
		// TODO Auto-generated method stub
		//log.info("++++++++++++++++++++++++++++");
		
		MacAddress macAddress = eth.getSourceMACAddress();
		
		if(securityPort.contains(switchPort) || !topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())) {

			//log.info("first");
			return RoutingAction.FORWARD_OR_FLOOD;
		}
		
		if(eth.getEtherType() == EthType.IPv4) {
			//log.info("ipv4");
			IPv4 ipv4 = (IPv4)eth.getPayload();
			IPv4Address address = ipv4.getSourceAddress();
			
			if(this.manager.check(switchPort, macAddress, address)) {
				//log.info("ipv4-check");
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else {
				//log.info("ipv4-none");
				return RoutingAction.NONE;
			}
			
			
		}
		else if(eth.getEtherType() == EthType.IPv6) {
			IPv6 ipv6 = (IPv6)eth.getPayload();
			IPv6Address address = ipv6.getSourceAddress();
			/*List<Binding<?>> list = getBindings();
			for(int i = 0 ; i < list.size() ; i++){
				log.info(list.get(i).getAddress().toString());
			}*/
			if(this.manager.check(switchPort, macAddress, address)) {
				//log.info("ipv6-check");
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else {
				//log.info("ipv6-none");
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			
		}
		else if(eth.getEtherType() == EthType.ARP) {
			//log.info("arp");
			ARP arp = (ARP)eth.getPayload();
			IPv4Address address = arp.getSenderProtocolAddress();
			
			if(this.manager.check(switchPort, address)) {
				//log.info("arp-check");
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else {
				//log.info("arp-none");
				return RoutingAction.NONE;
			}
			
		}
		//log.info("none");
		//log.info("================================");
		
		return RoutingAction.NONE;
	}
}
