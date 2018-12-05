package net.floodlightcontroller.savi.rest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.savi.flow.FlowAction;
import net.floodlightcontroller.savi.flow.FlowAction.FlowActionFactory;
import net.floodlightcontroller.savi.service.SAVIProviderService;

public class FlowResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(SAVIRest.class);
	
	/*
	 * 暂时拟定post提交的json格式如下：
	 * {
	 * 		"add":"swid=1,tid=0,in_port=1,priority=4,src_ipv6=fe80::200:ff,actions=output:2",
	 * 		"remove":"swid=1,tid=0,in_port=1,...src_ipv6=fe",
	 *		注：add2是专用下发验证规则的，下面的字段一个不能少，不过感觉eth_type=ipv6可以默认完成，省掉这个字段
	 * 		"add2":"swid=4,in_port=1,src_ipv6=fe80::200:ff:fe00:7,eth_type=ipv6,src_mac=00:00:00:00:00:07"
	 * }
	 * 两者的区别，remove里面的字段只有match的，add还要额外考虑actions
	 * 以上是思路1：只用一个url和FlowResource来处理所有流表的增删
	 * 
	 * 还有一条思路，那就是将add，remove单独抽取出来作为一个url，单独处理。
	 * 该情况的json格式如下：
	 * url:add
	 * {
	 * 		"swid":"1",
	 * 		"tid":"0",...
	 * }
	 * 先实现思路一，练练手
	 * 有个问题，就是流表的构造肯定没办法完整，也就是说可能忽略某些多余的值，怎么办呢？
	 * 暂时只找下面常量字符串吧，毕竟主要是下发绑定的专用流表，应该考虑的就是构造绑定类型的流表。
	 * 还有个问题，能定义的动作实在太多了，savi下发的规则大部分是绑定表，也就是转第二级流表。
	 * 这里需要区分action和instruction，action包含output（控制器or物理端口），instruction是转二级流表的。
	 * 动作1.action=output:0(1)，0这里定义为controller，其他表示物理端口
	 * 动作2.instruction=resubmit:1，1表示第二级流表。
	 * */
	public static final String FLOW_ADD="add";
	public static final String FLOW_REMOVE="remove";
	public static final String FLOW_MOD="mod";
	public static final String FLOW_TYPE="type";
	public static final String FLOW_ADD_2 = "add2";
	public static final String FLOW_MOD_2 = "mod2";
	
	//下面定义的是流表属性的常量字符串
	public static final String SWITCHID="swid";
	public static final String TABLEID="tid";
	public static final String INPORT="in_port";
	public static final String IPV6_SRC="src_ipv6";
	public static final String ETH_SRC="src_mac";
	public static final String ETH_TYPE="eth_type";
	public static final String PRIORITY="priority";
	public static final String IDLE_TIMEOUT="idle_timeout";
	public static final String HARD_TIMEOUT="hard_timeout";
	
	//定义验证规则和通配规则的优先级，后者为4
	public static final int BIND_PRIORITY = 5;
	//定义流表级数id
	public static final int BIND_TABLE_ID = 1;
	public static final int OTHER_TABLE_ID = 2;
	
	public static final String ACTION="action";
	public static final String OUTPUT="output";
	public static final String INSTRUCTION="instruction";
	public static final String RESUBMIT="resubmit";
	
	//获取相关Service以帮助下发流表
	SAVIProviderService saviProvider=null;
	
	//重点在于提交的数据，对底层网络的修改，所以不重视返回值的类型
	@Post
	public String post(String json){
		List<FlowAction> actions=new ArrayList<>();
		
		saviProvider=(SAVIProviderService)getContext().getAttributes()
		.get(SAVIProviderService.class.getCanonicalName());
		
		Map<String, String> jsonMap=SaviUtils.jsonToStringMap(json);
		for(Map.Entry<String, String> entry:jsonMap.entrySet()){
			Map<String,String> map=SaviUtils.splitToStringMap(entry.getValue());
			switch(entry.getKey()){
			case FLOW_ADD:
				doFlowAdd(map, actions);
				break;
			case FLOW_REMOVE:
				doFlowRemove(map, actions);
				break;
			case FLOW_MOD:
				doFlowMod(map, actions);
				break;
			case FLOW_ADD_2:
				doFlowAdd2(map, actions);
				break;
			case FLOW_MOD_2:
				doFlowMod2(map, actions);
				break;
			default:
				break;
			}
		}
		saviProvider.pushFlowActions(actions);
		return "{Success}";
	}
	
	public void doFlowAdd(Map<String, String> map,List<FlowAction> actions){
		if(map==null||map.size()==0) return;
		
		String swid=map.get(SWITCHID);
		if(swid==null||swid.isEmpty()) return;
		DatapathId dpId=DatapathId.of(1);
		//dpid是必须的字段，可以初始化为null，但tableid可能在循环中没有，必须有初始值
		OFPort port=OFPort.of(1);
		TableId tid=TableId.of(1);
		int priority=0;
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions=null;
		List<OFAction> ofActions=null;
		//为避免parseInt等转换出现运行时异常，对其进行捕捉
		try{
			for(String key:map.keySet()){
				if(key.equals(SWITCHID)){
					//dpId=DatapathId.of(Long.parseLong(swid));
					dpId = DatapathId.of(swid);
				}
				else if(key.equals(TABLEID)){
					tid=TableId.of(Integer.parseInt(map.get(key)));
				}
				else if(key.equals(INPORT)){
					mb.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
					port=OFPort.of(Integer.parseInt(map.get(key)));
				}
				else if(key.equals(IPV6_SRC)){
					mb.setExact(MatchField.IPV6_SRC, IPv6Address.of(map.get(key)));
				}
				else if(key.equals(ETH_SRC)){
					mb.setExact(MatchField.ETH_SRC, MacAddress.of(map.get(key)));
				}
				else if(key.equals(PRIORITY)){
					priority=Integer.parseInt(map.get(key));
				}
				else if(key.equals(ACTION)){
					String[] splits=map.get(key).split(":");
					if(splits.length<2||!splits[0].equals(OUTPUT))
						continue;
					ofActions=new ArrayList<>();
					//0号端口表示转交控制器,其他为物理端口，小于1的情况不考虑
					if(splits[1].equals("0")){
						ofActions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.CONTROLLER, Integer.MAX_VALUE));
					}
					else{
						ofActions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.of(Integer.parseInt(splits[1])), Integer.MAX_VALUE));
					}
				}
				else if(key.equals(INSTRUCTION)){
					String[] splits=map.get(key).split(":");
					if(splits.length<2||!splits[0].equals(RESUBMIT))
						continue;
					instructions=new ArrayList<>();
					instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(TableId.of(Integer.parseInt(splits[1]))));
				}
				
				
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		
		if(dpId.getLong()!=1&&port.getPortNumber()!=1) {
			saviProvider.getPushFlowToSwitchPorts().add(new SwitchPort(dpId, port));
		}
		
		try {
			Thread.sleep(1000);
			mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
			FlowAction action=FlowActionFactory.getFlowAddAction(
					dpId, tid, mb.build(), ofActions, instructions, priority);
			actions.add(action);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	//match中必须有dpid,in_port，可以说，这个方法是专门为了下发验证规则+配套规则的，所以优先级默认设定为5、4.
	public void doFlowAdd2(Map<String, String> map,List<FlowAction> actions){
		if(map==null||map.size()==0) return;
		
		String swid=map.get(SWITCHID);
		if(swid==null||swid.isEmpty()) return;
		String inport = map.get(INPORT);
		if(inport == null || inport.isEmpty()) return;
		
		DatapathId dpId=DatapathId.of(1);
		//dpid是必须的字段，可以初始化为null，但tableid可能在循环中没有，必须有初始值
		OFPort port=OFPort.of(1);
		TableId tid = TableId.of(1);
		int priority = BIND_PRIORITY;
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		Match.Builder mb2 = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions = null;
		
		//为避免parseInt等转换出现运行时异常，对其进行捕捉
		try{
			for(String key:map.keySet()){
				if(key.equals(SWITCHID)){
					dpId=DatapathId.of(swid);
				}
				else if(key.equals(INPORT)){
					mb.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
					mb2.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
					port=OFPort.of(Integer.parseInt(map.get(key)));
				}
				else if(key.equals(IPV6_SRC)){
					mb.setExact(MatchField.IPV6_SRC, IPv6Address.of(map.get(key)));
				}
				else if(key.equals(ETH_SRC)){
					mb.setExact(MatchField.ETH_SRC, MacAddress.of(map.get(key)));
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		
		if(dpId.getLong()!=1&&port.getPortNumber()!=1) {
			saviProvider.getPushFlowToSwitchPorts().add(new SwitchPort(dpId, port));
		}
		
		try {
			Thread.sleep(1000);
			instructions=new ArrayList<>();
			instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(TableId.of(2)));
			//这一条构造验证规则
			FlowAction action = FlowActionFactory.getFlowAddAction(
					dpId, tid, mb.build(), null, instructions, priority);
			//这一条构造通配规则，动作是丢包，优先级比上面的低一级
			FlowAction anyAction = FlowActionFactory.getFlowAddAction(
					dpId, tid, mb2.build(), null, null, priority - 1);
			
			actions.add(action);
			actions.add(anyAction);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public void doFlowMod2(Map<String, String> map,List<FlowAction> actions){
		if(map==null||map.size()==0) return;
		
		String swid=map.get(SWITCHID);
		if(swid==null||swid.isEmpty()) return;
		String inport = map.get(INPORT);
		if(inport == null || inport.isEmpty()) return;
		
		DatapathId dpId=DatapathId.of(1);
		//dpid是必须的字段，可以初始化为null，但tableid可能在循环中没有，必须有初始值
		TableId tid = TableId.of(1);
		int priority = BIND_PRIORITY;
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		Match.Builder mb2 = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions = null;
		int idleTimeout = 0;
		int hardTimeout = 0;
		
		//为避免parseInt等转换出现运行时异常，对其进行捕捉
		try{
			for(String key:map.keySet()){
				if(key.equals(SWITCHID)){
					dpId=DatapathId.of(swid);
				}
				else if(key.equals(INPORT)){
					mb.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
					mb2.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
				}
				else if(key.equals(IPV6_SRC)){
					mb.setExact(MatchField.IPV6_SRC, IPv6Address.of(map.get(key)));
				}
				else if(key.equals(ETH_SRC)){
					mb.setExact(MatchField.ETH_SRC, MacAddress.of(map.get(key)));
				}
				else if(key.equals(IDLE_TIMEOUT)){
					idleTimeout=Integer.parseInt(map.get(key));
				}
				else if(key.equals(HARD_TIMEOUT)){
					hardTimeout=Integer.parseInt(map.get(key));
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		instructions=new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(TableId.of(2)));
		//这一条构造验证规则
		FlowAction action = FlowActionFactory.getFlowModAction(
				dpId, tid, mb.build(), null, instructions, priority, hardTimeout, idleTimeout);
		//这一条构造通配规则，动作是丢包，优先级比上面的低一级
		FlowAction anyAction = FlowActionFactory.getFlowModAction(
				dpId, tid, mb2.build(), null, null, priority - 1, hardTimeout, idleTimeout);
		
		actions.add(action);
		actions.add(anyAction);
	}
	
	//还能设定idletimeout等
	public void doFlowMod(Map<String, String> map,List<FlowAction> actions){
		if(map==null||map.size()==0) return;
		
		String swid=map.get(SWITCHID);
		if(swid==null||swid.isEmpty()) return;
		DatapathId dpId=DatapathId.of(1);
		//dpid是必须的字段，可以初始化为null，但tableid可能在循环中没有，必须有初始值
		TableId tid=TableId.of(1);
		int priority=0;
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions=null;
		List<OFAction> ofActions=null;
		int idleTimeout=0;
		int hardTimeout=0;
		
		//为避免parseInt等转换出现运行时异常，对其进行捕捉
		try{
			for(String key:map.keySet()){
				if(key.equals(SWITCHID)){
					dpId=DatapathId.of(swid);
				}
				else if(key.equals(TABLEID)){
					tid=TableId.of(Integer.parseInt(map.get(key)));
				}
				else if(key.equals(INPORT)){
					mb.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
				}
				else if(key.equals(IPV6_SRC)){
					mb.setExact(MatchField.IPV6_SRC, IPv6Address.of(map.get(key)));
				}
				else if(key.equals(ETH_SRC)){
					mb.setExact(MatchField.ETH_SRC, MacAddress.of(map.get(key)));
				}
				else if(key.equals(PRIORITY)){
					priority=Integer.parseInt(map.get(key));
				}
				else if(key.equals(ACTION)){
					String[] splits=map.get(key).split(":");
					if(splits.length<2||!splits[0].equals(OUTPUT))
						continue;
					ofActions=new ArrayList<>();
					//0号端口表示转交控制器,其他为物理端口，小于1的情况不考虑
					if(splits[1].equals("0")){
						ofActions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.CONTROLLER, Integer.MAX_VALUE));
					}
					else{
						ofActions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.of(Integer.parseInt(splits[1])), Integer.MAX_VALUE));
					}
				}
				else if(key.equals(INSTRUCTION)){
					String[] splits=map.get(key).split(":");
					if(splits.length<2||!splits[0].equals(RESUBMIT))
						continue;
					instructions=new ArrayList<>();
					instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(TableId.of(Integer.parseInt(splits[1]))));
				}
				else if(key.equals(IDLE_TIMEOUT)){
					idleTimeout=Integer.parseInt(map.get(key));
				}
				else if(key.equals(HARD_TIMEOUT)){
					hardTimeout=Integer.parseInt(map.get(key));
				}
				
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		FlowAction action=FlowActionFactory.getFlowModAction(
				dpId, tid, mb.build(), ofActions, instructions, priority, hardTimeout, idleTimeout);
		actions.add(action);
	}
	
	public void doFlowRemove(Map<String, String> map,List<FlowAction> actions){
		//remove不同的地方就是，不需要考虑action等，只要swid、tableid和match即可
		if(map==null||map.size()==0) return;
		
		String swid=map.get(SWITCHID);
		if(swid==null||swid.isEmpty()) return;
		DatapathId datapathId=DatapathId.of(1);
		TableId tid=TableId.of(1);
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		
		OFPort port=OFPort.of(1);
		//为避免parseInt等转换出现运行时异常，对其进行捕捉
		try{
			for(String key:map.keySet()){
				if(key.equals(SWITCHID)){
					datapathId=DatapathId.of(swid);
				}
				else if(key.equals(TABLEID)){
					tid=TableId.of(Integer.parseInt(map.get(key)));
				}
				else if(key.equals(INPORT)){
					mb.setExact(MatchField.IN_PORT, OFPort.of(Integer.parseInt(map.get(key))));
				}
				else if(key.equals(IPV6_SRC)){
					mb.setExact(MatchField.IPV6_SRC, IPv6Address.of(map.get(key)));
				}
				else if(key.equals(ETH_SRC)){
					mb.setExact(MatchField.ETH_SRC, MacAddress.of(map.get(key)));
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		if(saviProvider.getPushFlowToSwitchPorts().contains(new SwitchPort(datapathId, port))) {
			log.info("交换机端口：  "+datapathId+"--"+port+"  不存在手动下发的验证规则，删除动作无效");
			return ;
		}
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		FlowAction action=FlowActionFactory.getFlowRemoveAction(
				datapathId, tid,mb.build());
		actions.add(action);
	}
	

}
