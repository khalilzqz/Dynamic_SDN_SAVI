package net.floodlightcontroller.savi.service;

import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.TableId;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.flow.FlowAction;

public interface SAVIProviderService extends IFloodlightService {
	
	public void addSAVIService(SAVIService service);
	public boolean pushActions(List<Action> actions);
	public boolean addSecurityPort(SwitchPort switchPort);
	public boolean delSecurityPort(SwitchPort switchPort);
	public Set<SwitchPort> getSecurityPorts();
	public List<Binding<?>> getBindings();

	public boolean pushFlowActions(List<FlowAction> actions);
	
	//新增同名方法
//	public void doFlowRemove(DatapathId switchId, TableId tableId, Match match,int priority);
	//当动态流表项比较多时，转为静态流表方案
	public void convertTable(DatapathId dpid, boolean toStatic);
	//手动转为静态流表
	public void convertTable(boolean toStatic);
	//手动转为默认
	public void convertToNone(DatapathId dpid);
	public void convertToNone();
	
	public Map<DatapathId, Integer> getPortsInBind();
	public Map<SwitchPort, Integer> getRank();
	public Set<DatapathId> getStaticSwId();
	public Set<DatapathId> getNoneSwId();
	public Map<SwitchPort, Integer> getHostWithPort();
	public Queue<SwitchPort> getNormalPorts();
	public Queue<SwitchPort> getAbnormalPorts();
	public Map<SwitchPort, Integer> getObservePorts();
	public Queue<SwitchPort> getStaticPorts();
	public Queue<SwitchPort> getNonePorts();
	public void doFlowRemove(DatapathId switchId, TableId tableId, Match match);
	public void doFlowAdd(DatapathId switchId, TableId tableId, Match match, List<OFAction> actions,
			List<OFInstruction> instructions, int priority);
	public Set<SwitchPort> getPushFlowToSwitchPorts();
	
	public boolean getInit();
	public void setInit(boolean flag);
}
