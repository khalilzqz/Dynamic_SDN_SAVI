package net.floodlightcontroller.savi;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowDeleteStrict;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.OFFlowModifyStrict;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFMeterMod;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionMeter;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.meterband.OFMeterBand;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.Action.ActionFactory;
import net.floodlightcontroller.savi.action.BindIPv4Action;
import net.floodlightcontroller.savi.action.BindIPv6Action;
import net.floodlightcontroller.savi.action.CheckIPv4BindingAction;
import net.floodlightcontroller.savi.action.CheckIPv6BindingAction;
import net.floodlightcontroller.savi.action.FloodAction;
import net.floodlightcontroller.savi.action.PacketOutAction;
import net.floodlightcontroller.savi.action.UnbindIPv4Action;
import net.floodlightcontroller.savi.action.UnbindIPv6Action;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.binding.BindingManager;
import net.floodlightcontroller.savi.flow.FlowAction;
import net.floodlightcontroller.savi.flow.FlowAddAction;
import net.floodlightcontroller.savi.flow.FlowModAction;
import net.floodlightcontroller.savi.flow.FlowRemoveAction;
import net.floodlightcontroller.savi.rest.SAVIRestRoute;
import net.floodlightcontroller.savi.service.SAVIProviderService;
import net.floodlightcontroller.savi.service.SAVIService;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyListener;
import net.floodlightcontroller.topology.ITopologyService;

/**
 * Provider
 * @author zhouyu
 *
 */
public class Provider implements IFloodlightModule, IOFSwitchListener, 
IOFMessageListener, ITopologyListener, SAVIProviderService, ILinkDiscoveryListener{
	
	
	/**
	 * Priority
	 */
	static final int PROTOCOL_LAYER_PRIORITY = 1;
	static final int SERVICE_LAYER_PRIORITY = 11;
	static final int BINDING_LAYER_PRIORITY = 5;
	static final int RELIABLE_PORT_PRIORITY = 5;
	
	static final long BAND_RATE = 10000;
	
	static final Logger log = LoggerFactory.getLogger(SAVIProviderService.class);
	
	
	protected boolean ENABLE_METER_TABLE = false;
	
	
	/**
	 * Floodlight service
	 */
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IDeviceService deviceService;
	protected ITopologyService topologyService;
	protected IRestApiService restApiService;
	protected IThreadPoolService threadPoolService;
	protected ILinkDiscoveryService linkDiscoveryService;
	
	protected SingletonTask updateTask;
	protected SingletonTask updateEntry;
	
	/**
	 * Service
	 */
	protected List<SAVIService> saviServices;
	protected BindingManager manager;
	
	/**
	 * rules 
	 */
	protected List<Match> serviceRules;
	protected List<Match> protocolRules;
	protected Set<SwitchPort> securityPort;
	protected Queue<LDUpdate> updateQueue;
	
	protected static final boolean ENABLE_FAST_FLOOD = true;
	
	public static final int SAVI_PROVIDER_APP_ID = 1000;
	public static TableId STATIC_TABLE_ID=TableId.of(0);
	public static TableId DYNAMIC_TABLE_ID=TableId.of(1);
	public static TableId FLOW_TABLE_ID = TableId.of(2);
	
	public static int securityTableCounter = 0;
	//定义更新时间
	private int updateTime;
	private int hardTimeout;
	//使用静态流表的交换机集合
	private volatile Set<DatapathId> staticSwId;
	//使用默认的交换机集合
	private volatile Set<DatapathId> noneSwId;
	//第一条流表项的优先级
	public static final int STATIC_FITST_PRIORITY=11111;
	//每个交换机上的加入绑定表的端口数
	private /*public static*/ Map<DatapathId, Integer> portsInBind;
	//交换机流量大小排名 即端口排名
	//<交换机绑定端口,BINDING_LAYER_PRIORITY = 5>
	private /*public static*/ Map<SwitchPort, Integer> rank;
	//<sw,端口对应的主机编号>
	private /*public static*/ Map<SwitchPort, Integer> hostWithPort	=new ConcurrentHashMap<>();
	//分别表示正常端口队列、异常端口队列
	private /*public static*/ Queue<SwitchPort> normalPorts = new ConcurrentLinkedQueue<>();
	private /*public static*/ Queue<SwitchPort> abnormalPorts = new ConcurrentLinkedQueue<>();
	private /*public static*/ Map<SwitchPort, Integer> observePorts = new ConcurrentHashMap<>();
	//静态交换机的主机
	private Queue<SwitchPort> staticPorts = new ConcurrentLinkedQueue<>();
	//默认交换机的主机
	private Queue<SwitchPort> nonePorts = new ConcurrentLinkedQueue<>();
	//手动下发流表一直存在
	private Set<SwitchPort> pushFlowToSwitchPorts=new HashSet<>(); 
	
	//dynamic flag
	private boolean alreadyInit =true;
	//记录三个状态 默认 动态 静态
	private byte status=0;
	/**
	 * Static cookie 
	 */
	static {
		AppCookie.registerApp(SAVI_PROVIDER_APP_ID, "Forwarding");
	}
	public static final U64 cookie = AppCookie.makeCookie(SAVI_PROVIDER_APP_ID, 0);
	
	/**
	 * Process packet in message.
	 * @param sw
	 * @param pi
	 * @param cntx
	 */
	/*protected Command processPacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IRoutingDecision decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
		
		SwitchPort switchPort = new SwitchPort(sw.getId(), inPort);
		RoutingAction routingAction = null;
		
		if (decision == null) {
			decision = new RoutingDecision(sw.getId(), inPort,
					IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), RoutingAction.FORWARD);
		}
		
		if(topologyService.isEdge(sw.getId(), inPort)) {
		// SAVI service process
			for(SAVIService s : saviServices) {
				if (s.match(eth)) {
					//log.info(s.toString());
					routingAction = s.process(switchPort, eth);
					break;
				}
			}
		}
		
		// Process
		if(routingAction == null) {
			 routingAction = process(switchPort, eth);
		}
		
		if(routingAction != null) {
			decision.setRoutingAction(routingAction);
		}
		
		decision.addToContext(cntx);
		
		return Command.CONTINUE;
		
	}*/
	//新增DeviceService的信息
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IRoutingDecision decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
		/*IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);
		if(dstDevice == null) {
			log.info("no dstdevice");
		}*/
		
		SwitchPort switchPort = new SwitchPort(sw.getId(), inPort);
		RoutingAction routingAction = null;
		
		if (decision == null) {
			decision = new RoutingDecision(sw.getId(), inPort,
					IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), RoutingAction.FORWARD);
		}
		
		if(topologyService.isEdge(sw.getId(), inPort)) {
		//	System.out.println(sw.getId());
		// SAVI service process
			for(SAVIService s : saviServices) {
				if (s.match(eth)) {
				//	log.info(s.toString());
					routingAction = s.process(switchPort, eth);
					break;
				}
			}
		}
		
		// Process
		if(routingAction == null) {
			routingAction = process(switchPort, eth);
		}
		
		if(routingAction != null) {
			decision.setRoutingAction(routingAction);
		}
		
		decision.addToContext(cntx);
		
		return Command.CONTINUE;
		
	}
	
	/**
	 * Add savi servie to provider
	 * @param service
	 */
	@Override
	public void addSAVIService(SAVIService service) {
		saviServices.add(service);
		serviceRules.addAll(service.getMatches());
	}
	
	/**
	 * Process actions from savi service.
	 * @param actions
	 */
	@Override
	public boolean pushActions(List<Action> actions) {
		for(Action action:actions){
			switch(action.getType()){
			case FLOOD:
				doFlood((FloodAction)action);
				break;
			case PACKET_OUT:
			case PACKET_OUT_MULTI_PORT:
				doPacketOut((PacketOutAction)action);
				break;
			case BIND_IPv4:
				doBindIPv4((BindIPv4Action)action);
				break;
			case BIND_IPv6:
				doBindIPv6((BindIPv6Action)action);
				break;
			case UNBIND_IPv4:
				doUnbindIPv4((UnbindIPv4Action)action);
				break;
			case UNBIND_IPv6:
				doUnbindIPv6((UnbindIPv6Action)action);
				break;
			case CHECK_IPv4_BINDING:
				return doCheckIPv4BInding((CheckIPv4BindingAction)action);
			case CHECK_IPv6_BINDING:
				return doCheckIPv6Binding((CheckIPv6BindingAction)action);
			default:
				break;
			}
		}
		return true;
	}
	
	public boolean pushFlowActions(List<FlowAction> actions){
		for(FlowAction action:actions){
			switch(action.getType()){
			case ADD:
				doFlowAdd((FlowAddAction)action);
				break;
			case MOD:
				doFlowMod((FlowModAction)action);
				break;
			case REMOVE:
				doFlowRemove((FlowRemoveAction)action);
				break;
			default:
				break;
			}
		}
		return true;
	}
	
		
	//更新定时流表项方法
	public void updateTimingFlowEntry(int hardTimeout, Set<DatapathId> staticSwIds) {
		
		for(DatapathId dpid:portsInBind.keySet()) {
			if(staticSwIds==null||!staticSwIds.contains(dpid)) {
				updateTimingFlowEntry(hardTimeout, dpid);
			}
		}
	}
	
	public void updateTimingFlowEntry(int hardTimeout, DatapathId dpid) {
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions=new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(DYNAMIC_TABLE_ID));
		
		doFlowMod(dpid, STATIC_TABLE_ID, mb.build(), null, instructions, STATIC_FITST_PRIORITY, hardTimeout, 0);
	}
	
	private void AddTimingFlowEntry(int hardTimeout, DatapathId dpid) {
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions=new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(DYNAMIC_TABLE_ID));
		
		doFlowAdd(dpid, STATIC_TABLE_ID, mb.build(), null, instructions, STATIC_FITST_PRIORITY, hardTimeout, 0);
	}
	
	//手动转为静态savi
	@Override
	public void convertTable(boolean isTrue) {
		for(DatapathId dpid : portsInBind.keySet()) {
			convertTable(dpid,isTrue);
		}
		alreadyInit=!isTrue;
	}
	
	//手动转为默认
	public void convertToNone(DatapathId dpid) {
		if(noneSwId.contains(dpid)){
			log.warn("交换机："+dpid+"已经是默认的，无需转换");
			return ;
		}
		noneSwId.add(dpid);
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions=new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
		List<SwitchPort> tmp = new ArrayList<>(rank.keySet());
		for(int i = 0; i < tmp.size(); i++) {
			if(tmp.get(i).getSwitchDPID().equals(dpid)) {
				nonePorts.offer(tmp.get(i));
			}
		}
		if(staticSwId.contains(dpid)){
			staticSwId.remove(dpid);
			int len = staticPorts.size();
			for(int i = 0; i < len; i++) {
				if(staticPorts.element().getSwitchDPID().equals(dpid)) {
					staticPorts.poll();
				}
			}
		}else{
			doFlowRemove(dpid, STATIC_TABLE_ID, mb.build(), STATIC_FITST_PRIORITY);
		}
		doFlowAdd(dpid, STATIC_TABLE_ID, mb.build(), null, instructions, STATIC_FITST_PRIORITY);
		log.warn("交换机{"+dpid+"}转为默认");
	}
	
	public void convertToNone() {
		for(DatapathId dpid : portsInBind.keySet()) {
			convertToNone(dpid);
		}
		alreadyInit=false;
	}
	
	//当动态流表项比较多时，转为静态流表方案
	@Override
	public void convertTable(DatapathId dpid, boolean isTrue) {
		if(!portsInBind.containsKey(dpid)) {
			log.warn("交换机 "+dpid+" 不是边缘交换机，不用转换");
			return ;
		}
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		if(isTrue) {
			if(staticSwId.contains(dpid)) {
//				log.warn("交换机{"+dpid+"}里的验证流表已经是静态流表，无需转换");
				return ;
			}
			staticSwId.add(dpid);
			IOFSwitch sw=switchService.getSwitch(dpid);
		//	System.out.println("交换机:" + sw + "端口：" + sw.getEnabledPortNumbers());
			List<SwitchPort> tmp=new ArrayList<>(rank.keySet());
			for(int i = 0; i < tmp.size(); i++) {
				if(tmp.get(i).getSwitchDPID().equals(dpid)) {
					staticPorts.offer(tmp.get(i));
			//		System.out.println("端口：" + hostWithPort.get(tmp.get(i)));
				}
			}
			System.out.println("交换机：" + dpid);
			if(noneSwId.contains(dpid)) {
				noneSwId.remove(dpid);
				int len = nonePorts.size();
				for(int i = 0; i < len; i++) {
					if(nonePorts.element().getSwitchDPID().equals(dpid)) {
						System.out.println("端口：" + nonePorts.peek());
						nonePorts.poll();
					}
				}
				
			}
			doFlowRemove(dpid, STATIC_TABLE_ID, mb.build(), STATIC_FITST_PRIORITY);
			log.warn("交换机{"+dpid+"}转为静态流表");
		//	getStaticPorts();
		}else {
			if(!staticSwId.contains(dpid)&&!noneSwId.contains(dpid)) {
//				log.warn("交换机{"+dpid+"}里的验证流表就是动态流表，无需转换");
				return ;
			}
			List<OFInstruction> instructions=new ArrayList<>();
			instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
			if(staticSwId.contains(dpid)) {
				staticSwId.remove(dpid);
				int len = staticPorts.size();
				for(int i = 0; i < len; i++) {
					if(staticPorts.element().getSwitchDPID().equals(dpid)) {
						staticPorts.poll();
					}
				}
			}else{
				doFlowRemove(dpid, STATIC_TABLE_ID, mb.build(), STATIC_FITST_PRIORITY);
				noneSwId.remove(dpid);
				int len = nonePorts.size();
				for(int i = 0; i < len; i++) {
					if(nonePorts.element().getSwitchDPID().equals(dpid)) {
						nonePorts.poll();
					}
				}
			}
			doFlowAdd(dpid, STATIC_TABLE_ID, mb.build(), null, instructions, STATIC_FITST_PRIORITY);
			alreadyInit=true;
			log.warn("交换机{"+dpid+"}转为动态流表");
		}
	}
	
	/**
	 * 
	 */
	@Override
	public String getName() {
		return "savi";
	}

	/**
	 * Floodlight override function
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")));//(type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")));
	}

	/**
	 * Floodlight override function
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return type.equals(OFType.PACKET_IN) && name.equals("forwarding");//type.equals(OFType.PACKET_IN) || name.equals("forwarding");
	}

	/**
	 * Dispatch openflow message
	 * @param sw
	 * @param msg
	 * @param cntx
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		
		switch (msg.getType()) {
		case PACKET_IN:
			return processPacketIn(sw, (OFPacketIn) msg, cntx);
		case ERROR:
			log.info("ERROR");
		default:
			break;
		}
		
		return Command.CONTINUE;
	}

	/**
	 * Module service
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> services = new ArrayList<Class<? extends IFloodlightService>>();
		services.add(SAVIProviderService.class);
		return services;
	}

	/**
	 * Service implementation.
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> serviceImpls = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		serviceImpls.put(SAVIProviderService.class, this);
		return serviceImpls;
	}

	/**
	 * Module dependencies.
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> dependencies = new ArrayList<Class<? extends IFloodlightService>>();
		dependencies.add(IFloodlightProviderService.class);
		dependencies.add(IOFSwitchService.class);
		dependencies.add(IDeviceService.class);
		dependencies.add(ITopologyService.class);
		dependencies.add(IStorageSourceService.class);
		dependencies.add(IRestApiService.class);
		dependencies.add(IThreadPoolService.class);
		dependencies.add(ILinkDiscoveryService.class);
		return dependencies;
	}

	/**
	 * Initialize module.
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider 	 = context.getServiceImpl(IFloodlightProviderService.class);
		switchService 	   	 = context.getServiceImpl(IOFSwitchService.class);
		deviceService 	   	 = context.getServiceImpl(IDeviceService.class);
		topologyService 	 = context.getServiceImpl(ITopologyService.class);
		restApiService 		 = context.getServiceImpl(IRestApiService.class);
		threadPoolService	 = context.getServiceImpl(IThreadPoolService.class);
		linkDiscoveryService = context.getServiceImpl(ILinkDiscoveryService.class);
		
		updateQueue = new ConcurrentLinkedQueue<>();
		
		saviServices 		= new ArrayList<>();
		manager 			= new BindingManager();
		
		serviceRules		= new ArrayList<>();
		protocolRules		= new ArrayList<>();
		
		
		updateTime=6;
		hardTimeout=18;
		staticSwId=new HashSet<>();
		noneSwId = new HashSet<>();
		portsInBind=new HashMap<>();
		rank=new HashMap<>();
		
		{
			Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
			mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
			protocolRules.add(mb.build());
		
			mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
			mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			protocolRules.add(mb.build());
		}
		
		securityPort = new HashSet<>();
		
		{
			// set security port.
			// SwitchPort switchPort = new SwitchPort(DatapathId.of(1L),OFPort.of(1));
			// securityPort.add(switchPort);
		}
		
		Map<String, String> configParameters = context.getConfigParams(this);
		if(configParameters.containsKey("enable-meter-table")) {
			if(configParameters.get("enable-meter-table").equals("YES")) {
				ENABLE_METER_TABLE = true;
			}
			else {
				ENABLE_METER_TABLE = false;
			}
		}
		else {
			ENABLE_METER_TABLE = false;
		}
		
	} 

	/**
	 * Start up module
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.ERROR, this);
		switchService.addOFSwitchListener(this);
		restApiService.addRestletRoutable(new SAVIRestRoute());
		linkDiscoveryService.addListener(this);
		
		ScheduledExecutorService ses = threadPoolService.getScheduledExecutor();
		
		updateTask = new SingletonTask(ses, new Runnable() {
			
			@Override
			public void run() {
				while(updateQueue.peek() != null){
					LDUpdate update = updateQueue.remove();
					switch(update.getOperation()){
					case PORT_UP:
//						log.info("Provider line 569,port up");
						if(!topologyService.isEdge(update.getSrc(), update.getSrcPort())){
							securityPort.add(new SwitchPort(update.getSrc(), update.getSrcPort()));
						}else {
//							normalPorts.offer(new SwitchPort(update.getSrc(), update.getSrcPort()));
						}
						break;
					case PORT_DOWN:
						SwitchPort sp=new SwitchPort(update.getSrc(), update.getSrcPort());
						if(normalPorts.contains(sp)) {
							normalPorts.remove(sp);
						}else if(observePorts.containsKey(sp)) {
							observePorts.remove(sp);
						}else if(abnormalPorts.contains(sp)) {
							abnormalPorts.remove(sp);
						}
						break;
					default:
					}
					
					/*
					log.info("Provider line 582");
					for(DatapathId dpid:switchService.getAllSwitchDpids()) {
						IOFSwitch sw = switchService.getActiveSwitch(dpid);
						for(OFPort port:sw.getEnabledPortNumbers()) {
							if(!topologyService.isEdge(dpid, port) && !securityPort.contains(new SwitchPort(dpid, port))) {
								log.info("Provider line 588，"+dpid.toString()+"-"+port.toString());
								List<OFInstruction> instructions = new ArrayList<>();
								instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
								Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
								mb.setExact(MatchField.IN_PORT, port);
								//静态savi验证流表  对非边缘交换机端口设置指令  所有交换机端口
								doFlowMod(dpid, STATIC_TABLE_ID, mb.build(), null, instructions, BINDING_LAYER_PRIORITY,0,0);
							}
						}
					}
					*/
				}
				updateTask.reschedule(1000, TimeUnit.MILLISECONDS);
			}
		});
		updateTask.reschedule(100, TimeUnit.MILLISECONDS);
		
		//更新流表项的硬老化时间
		ScheduledExecutorService ses1=threadPoolService.getScheduledExecutor();
		updateEntry=new SingletonTask(ses1, new Runnable() {
			
			@Override
			public void run() {
				updateTimingFlowEntry(hardTimeout,staticSwId);
				updateEntry.reschedule(updateTime, TimeUnit.SECONDS);
			}
		});
		updateEntry.reschedule(updateTime, TimeUnit.SECONDS);
				
	}
	
	/**
	 * Listen switch add message.
	 */
	@Override
	public void switchAdded(DatapathId switchId) {
		
		manager.addSwitch(switchId);
		
//		log.info("新的交换机"+switchId+"加入网络");
		
		//table-miss 静态流表(默认到转发表，后面看情况修改)
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions = new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
		//注释
		doFlowAdd(switchId, STATIC_TABLE_ID, mb.build(), null, instructions, 0);
		//转发表通配规则
		List<OFAction> actions = new ArrayList<>();
		actions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.CONTROLLER, Integer.MAX_VALUE));
		doFlowAdd(switchId, FLOW_TABLE_ID, mb.build(), actions, null, 0);
	
		
	}
	
	private void addSpecialFlowEntry(DatapathId switchId) {	
		
		
		Match.Builder mb=OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		List<OFInstruction> instructions = new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
		
		//这里三个顺序不能错
		//table-miss，动态流表
		doFlowAdd(switchId, DYNAMIC_TABLE_ID, mb.build(), null, instructions, 0, 0, 0);
//		set.add(new ValidationRuleFlowEntry(DYNAMIC_TABLE_ID.getValue(), 0, 0, null, "to table 2"));
		
		//静态流表转动态流表
		AddTimingFlowEntry(hardTimeout, switchId);
//		set.add(new ValidationRuleFlowEntry(STATIC_TABLE_ID.getValue(), hardTimeout, STATIC_FITST_PRIORITY, null, "to table 1"));
		
		//修改table-miss 静态流表 drop
		doFlowMod(switchId, STATIC_TABLE_ID, mb.build(), null, null, 0,0,0);
		/*
		for(ValidationRuleFlowEntry validationRuleFlowEntry : set) {
			if(validationRuleFlowEntry.getTableId()==STATIC_TABLE_ID.getValue()&&validationRuleFlowEntry.getPriority()==0) {
				validationRuleFlowEntry.setAction("drop");
			}
		}
		*/
		for(Match match:serviceRules){
			
			List<OFAction> actions = new ArrayList<>();
			
			actions.add(OFFactories.getFactory(OFVersion.OF_13).actions().output(OFPort.CONTROLLER, Integer.MAX_VALUE));
			
			if(ENABLE_METER_TABLE) {
				List<OFInstruction> instructions1 = new ArrayList<OFInstruction>();
				OFInstructionMeter meter = OFFactories.getFactory(OFVersion.OF_13).instructions().buildMeter()
						.setMeterId(1)
						.build();
  
				OFInstructionApplyActions output = OFFactories.getFactory(OFVersion.OF_13).instructions().buildApplyActions().setActions(actions).build();
			
				instructions1.add(meter);
				instructions1.add(output);
				
				doFlowAdd(switchId, STATIC_TABLE_ID, match, null, instructions1, SERVICE_LAYER_PRIORITY);
			} else {
				//DHCP协议和SLAAC协议通信时 设置的匹配规则(静态流表规则)
				doFlowAdd(switchId, STATIC_TABLE_ID, match, actions, null, SERVICE_LAYER_PRIORITY);
			}
			
		}
		
		
		/*for(SwitchPort switchPort:securityPort){
			if(!switchId.equals(switchPort.getSwitchDPID())) continue;
			log.info("Provider line:582，reliable port " + switchPort.getSwitchDPID().toString() + "-" + switchPort.getPort().toString());
			mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
			mb.setExact(MatchField.IN_PORT, switchPort.getPort());
				
			instructions = new ArrayList<>();
			instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
			//对于可信端口来的数据直接跳到转发表
			doFlowAdd(switchPort.getSwitchDPID(), STATIC_TABLE_ID, mb.build(), null, instructions, RELIABLE_PORT_PRIORITY,0,0);
		}*/
		
	}

	/**
	 * Listen switch remove message.
	 */
	@Override
	public void switchRemoved(DatapathId switchId) {
		manager.removeSwitch(switchId);
		List<Action> actions = new ArrayList<>();
		actions.add(ActionFactory.getClearSwitchBindingAction(switchId));
		for(SAVIService s:saviServices){
			s.pushActins(actions);
		}
	}

	@Override
	public void switchActivated(DatapathId switchId) {

	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {

	}

	@Override
	public void switchChanged(DatapathId switchId) {
		
	}
	
	/**
	 * Process the frame
	 * @param switchPort
	 * @param eth
	 * @return routing acttion
	 */
	protected RoutingAction process(SwitchPort switchPort, Ethernet eth){
		MacAddress macAddress = eth.getSourceMACAddress();
		//log.info("1");
		if(securityPort.contains(switchPort) || !topologyService.isEdge(switchPort.getSwitchDPID(), switchPort.getPort())){
				return RoutingAction.FORWARD_OR_FLOOD;
		}
		
		if(eth.getEtherType() == EthType.IPv4){
			//log.info("12");
			IPv4 ipv4 = (IPv4)eth.getPayload();
			IPv4Address address = ipv4.getSourceAddress();
			if(manager.check(switchPort, macAddress, address)){
				//doFlood(switchPort, eth.serialize());
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else if(address.isUnspecified()){
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else {
				return RoutingAction.FORWARD_OR_FLOOD;
			}
		}
		else if(eth.getEtherType() == EthType.IPv6){
			//log.info("123");
			IPv6 ipv6 = (IPv6)eth.getPayload();
			IPv6Address address = ipv6.getSourceAddress();
			if(address.isUnspecified()){
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else if(manager.check(switchPort, macAddress, address)){
				if(ipv6.getDestinationAddress().isBroadcast()
						||ipv6.getDestinationAddress().isMulticast()){
					return RoutingAction.MULTICAST;
				}
				else{
					
					return RoutingAction.FORWARD_OR_FLOOD;
				}
				
			}
			else{
				return RoutingAction.NONE;
			}
		}
		else if(eth.getEtherType() == EthType.ARP){
			ARP arp = (ARP)eth.getPayload();
			IPv4Address address = arp.getSenderProtocolAddress();
			//log.info("12344");
			if(manager.check(switchPort, macAddress, address)){
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else if(address.isUnspecified()){
				return RoutingAction.FORWARD_OR_FLOOD;
			}
			else {
				return RoutingAction.NONE;
			}
			
		}
		//log.info("2");
		return null;
	}
	
	/**
	 * Do flood
	 * @param action
	 */
	protected void doFlood(FloodAction action){
		SwitchPort inSwitchPort = new SwitchPort(action.getSwitchId(), action.getInPort());
		byte[] data = action.getEthernet().serialize();
		doFlood(inSwitchPort, data);
	}
	/**
	 * Do flood.
	 * @param inSwitchPort
	 * @param data
	 */
	protected void doFlood(SwitchPort inSwitchPort, byte[] data){
		if(ENABLE_FAST_FLOOD) {
			doFastFlood(inSwitchPort, data);
			return;
		}
		
		Collection<? extends IDevice> tmp = deviceService.getAllDevices();
		for (IDevice d : tmp) {
			SwitchPort[] switchPorts = d.getAttachmentPoints();
			for (SwitchPort switchPort : switchPorts) {
				if (!switchPort.equals(inSwitchPort)) {
					doPacketOut(switchPort, data);
				}
			}
		}
	}
	
	protected void doFastFlood(SwitchPort inPort, byte[] data) {
		List<OFPort> ports = new ArrayList<>();
		
		IOFSwitch sw = switchService.getSwitch(inPort.getSwitchDPID());
		
		for(OFPort port: sw.getEnabledPortNumbers()) {
			if(!port.equals(inPort.getPort())&&topologyService.isEdge(sw.getId(), port)) {
				doPacketOut(new SwitchPort(inPort.getSwitchDPID(), port), data);
			}
		}
		
		for(DatapathId switchId: switchService.getAllSwitchDpids()) {
			if(!switchId.equals(inPort.getSwitchDPID())) {
				sw = switchService.getSwitch(switchId);
				ports.clear();
				
				for(OFPort port: sw.getEnabledPortNumbers()) {
					if(topologyService.isEdge(sw.getId(), port)) {
						doPacketOut(new SwitchPort(switchId, port), data);
					}
				}
			}
		}
		
	}
	
	/**
	 * Do packet out.
	 * @param action
	 */
	protected void doPacketOut(PacketOutAction action) {
		
		doPacketOut(action.getSwitchId(),
					action.getInPort(),
					action.getOutPorts(),
					action.getEthernet().serialize());
	
	}
	
	/**
	 * Do packet out
	 * @param switchPort
	 * @param data
	 */
	protected void doPacketOut(SwitchPort switchPort, byte[] data) {
		
		IOFSwitch sw = switchService.getActiveSwitch(switchPort.getSwitchDPID());
		OFPort port = switchPort.getPort();
		
		
		try {
			OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
			
			List<OFAction> actions = new ArrayList<OFAction>();
			actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
			
			pob.setActions(actions)
			   .setBufferId(OFBufferId.NO_BUFFER)
			   .setData(data)
			   .setInPort(OFPort.CONTROLLER);
			
			sw.write(pob.build());
			
		} catch (NullPointerException e) {
			
		}
	}
	
	/**
	 * Do packet out
	 * @param switchId
	 * @param inPort
	 * @param outPorts
	 * @param data
	 */
	protected void doPacketOut(DatapathId switchId, OFPort inPort, List<OFPort> outPorts, byte[] data) {
		
		IOFSwitch sw = switchService.getActiveSwitch(switchId);
		
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		
		List<OFAction> actions = new ArrayList<OFAction>();
		for(OFPort port:outPorts) {
			actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
		}
		
		pob.setActions(actions)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setData(data)
		   .setInPort(inPort);
		
		sw.write(pob.build());
	}
	
	/**
	 * Do bind ipv4.
	 * @param action
	 */
	protected void doBindIPv4(BindIPv4Action action){
		Binding<?> binding = action.getBinding();
		log.info("BIND "+binding.getAddress());
		
		manager.addBinding(binding);
		
		if(securityPort.contains(binding.getSwitchPort())){
			return;
		}
		
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_SRC, binding.getMacAddress());
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		mb.setExact(MatchField.IPV4_SRC, (IPv4Address)binding.getAddress());
		mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
		
		List<OFInstruction> instructions = new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
		doFlowAdd(binding.getSwitchPort().getSwitchDPID(), STATIC_TABLE_ID, mb.build(), null, instructions, BINDING_LAYER_PRIORITY);	
	}
	
	/**
	 * Do bind ipv6
	 * @param action
	 */
	protected void doBindIPv6(BindIPv6Action action){
		Binding<?> binding = action.getBinding();
		log.info("BIND "+binding.getAddress().toString()+"  "+binding.getSwitchPort().getSwitchDPID());
		
		manager.addBinding(binding);
		
		if(securityPort.contains(binding.getSwitchPort())){
			return;
		}
		
		if(!portsInBind.containsKey(binding.getSwitchPort().getSwitchDPID())){
			addSpecialFlowEntry(binding.getSwitchPort().getSwitchDPID());
			portsInBind.put(binding.getSwitchPort().getSwitchDPID(), 1);
		}else {
			portsInBind.put(binding.getSwitchPort().getSwitchDPID(), 1+portsInBind.get(binding.getSwitchPort().getSwitchDPID()));
		}
		
		//下发静态流表
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_SRC, binding.getMacAddress());
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		mb.setExact(MatchField.IPV6_SRC, (IPv6Address)binding.getAddress());
		mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
		
		List<OFInstruction> instructions = new ArrayList<>();
		instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
		//注释
		doFlowAdd(binding.getSwitchPort().getSwitchDPID(), STATIC_TABLE_ID, mb.build(), null, instructions, BINDING_LAYER_PRIORITY);
		rank.put(binding.getSwitchPort(), BINDING_LAYER_PRIORITY);
		hostWithPort.put(binding.getSwitchPort(), (int)(binding.getMacAddress().getLong()));
	}
	
	/**
	 * Do unbind ipv4.
	 * @param action
	 */
	protected void doUnbindIPv4(UnbindIPv4Action action) {
		manager.delBinding(action.getIpv4Address());
		Binding<?> binding = action.getBinding();
		if(securityPort.contains(binding.getSwitchPort())){
			return;
		}
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_SRC, binding.getMacAddress());
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		mb.setExact(MatchField.IPV4_SRC, (IPv4Address)binding.getAddress());
		mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
		
		doFlowRemove(binding.getSwitchPort().getSwitchDPID(), STATIC_TABLE_ID, mb.build());
	}
	
	/**
	 * Do unbind ipv6.
	 * @param action
	 */
	protected void doUnbindIPv6(UnbindIPv6Action action) {
		manager.delBinding(action.getIPv6Address());
		
		Binding<?> binding = action.getBinding();
		if(securityPort.contains(binding.getSwitchPort())){
			return;
		}
		
		portsInBind.put(binding.getSwitchPort().getSwitchDPID(), portsInBind.get(binding.getSwitchPort().getSwitchDPID())-1);
		
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
		doFlowRemove(binding.getSwitchPort().getSwitchDPID(), STATIC_TABLE_ID, mb.build());

		System.out.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$解绑发生了");
		
		rank.remove(binding.getSwitchPort());
//		if(observePorts.containsKey(binding.getSwitchPort())) {
//			observePorts.remove(binding.getSwitchPort());
//		}else if(abnormalPorts.contains(binding.getSwitchPort())) {
//			abnormalPorts.remove(binding.getSwitchPort());
//		}else {
//			normalPorts.remove(binding.getSwitchPort());
//		}
		hostWithPort.remove(binding.getSwitchPort());
		/* 这里不能保留 动态的这个流表项不一定存在，删除会报错
		//删除动态验证流表
		Match.Builder mb1 = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		mb.setExact(MatchField.IN_PORT, binding.getSwitchPort().getPort());
		doFlowRemove(binding.getSwitchPort().getSwitchDPID(), DYNAMIC_TABLE_ID, mb1.build());
		*/
	}
	
	/**
	 * Do check
	 * @param action
	 * @return
	 */
	protected boolean doCheckIPv4BInding(CheckIPv4BindingAction action){
		return manager.check(action.getSwitchPort(), action.getMacAddress(), action.getIPv4Address());
	}
	
	/**
	 * Do check
	 * @param action
	 * @return
	 */
	protected boolean doCheckIPv6Binding(CheckIPv6BindingAction action) {
		return manager.check(action.getSwitchPort(), action.getMacAddress(), action.getIPv6Address());
	}
	
	protected void doMeterMod(DatapathId switchId, long meterId,List<OFMeterBand> bands) {
		OFMeterMod.Builder meterBuilder = OFFactories.getFactory(OFVersion.OF_13).buildMeterMod().setMeterId(meterId);//.setBands(bands);
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(meterBuilder.build());
		}
	}
	
	/**
	 * Do flow modification.
	 * @param switchId
	 * @param tableId
	 * @param match
	 * @param actions
	 * @param instructions
	 * @param priority
	 */
	protected void doFlowMod(FlowModAction action) {
		doFlowMod(action.getSwitchId(),
				action.getTableId(),
				action.getMatch(),
				action.getActions(),
				action.getInstructions(),
				action.getPriority(), 
				action.getHardTimeout(), action.getIdleTimeout());
	}
	
	protected void doFlowMod(DatapathId switchId,TableId tableId,Match match, List<OFAction> actions, List<OFInstruction> instructions,int priority){
		OFFlowModify.Builder fab = OFFactories.getFactory(OFVersion.OF_13).buildFlowModify();
		
		fab.setCookie(cookie)
		   .setTableId(tableId)
		   .setHardTimeout(0)
		   .setIdleTimeout(0)
		   .setPriority(priority)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setMatch(match);
		
		if(actions != null){
			fab.setActions(actions);
		}
		
		if(instructions != null){
			fab.setInstructions(instructions);
		}
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(fab.build());
		}
	}
	
	//strict
	protected void doFlowMod(DatapathId switchId,TableId tableId,Match match, List<OFAction> actions, List<OFInstruction> instructions,int priority, int hardTimeout,int idleTimeout){
		OFFlowModifyStrict.Builder fab = OFFactories.getFactory(OFVersion.OF_13).buildFlowModifyStrict();
		
		fab.setCookie(cookie)
		.setTableId(tableId)
		.setHardTimeout(hardTimeout)
		.setIdleTimeout(idleTimeout)
		.setPriority(priority)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(match);
		
		if(actions != null){
			fab.setActions(actions);
		}
		
		if(instructions != null){
			fab.setInstructions(instructions);
		}
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(fab.build());
		}
		
	}
	
	/**
	 * Do flow modification.
	 * @param switchId
	 * @param tableId
	 * @param match
	 * @param actions
	 * @param instructions
	 * @param priority
	 */
	protected void doFlowAdd(FlowAddAction action) {
		doFlowAdd(action.getSwitchId(), 
				action.getTableId(), 
				action.getMatch(),
				action.getActions(), 
				action.getInstructions(),
				action.getPriority());
	}
	
	@Override
	public void doFlowAdd(DatapathId switchId,TableId tableId,Match match, List<OFAction> actions, List<OFInstruction> instructions,int priority) {
		doFlowAdd(switchId, tableId, match, actions, instructions, priority,0,0);
	}
	
	protected void doFlowAdd(DatapathId switchId,TableId tableId,Match match, List<OFAction> actions, List<OFInstruction> instructions,int priority,int hardTimeout, int idleTimeout){
		OFFlowAdd.Builder fab = OFFactories.getFactory(OFVersion.OF_13).buildFlowAdd();
		
		fab.setCookie(cookie)
		   .setTableId(tableId)
		   .setHardTimeout(hardTimeout)
		   .setIdleTimeout(idleTimeout)
		   .setPriority(priority)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setMatch(match);
		
		if(actions != null){
			fab.setActions(actions);
		}
		
		if(instructions != null){
			fab.setInstructions(instructions);
		}
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(fab.build());
		}
	}
	
	/**
	 * Do flow remove
	 * @param switchId
	 * @param tableId
	 * @param match
	 */
	protected void doFlowRemove(FlowRemoveAction action) {
		doFlowRemove(action.getSwitchId(),
				action.getTableId(),
				action.getMatch());
	}
	
	@Override
	public void doFlowRemove(DatapathId switchId, TableId tableId, Match match) {
		OFFlowDelete.Builder fdb = OFFactories.getFactory(OFVersion.OF_13).buildFlowDelete();
		
		fdb.setMatch(match)
		   .setCookie(cookie)
		   .setTableId(tableId)
		   .setBufferId(OFBufferId.NO_BUFFER);
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(fdb.build());
		}
	}
	
	
	//新增doFlowRemove同名方法，参数增加优先级
	public void doFlowRemove(DatapathId switchId, TableId tableId, Match match,int priority) {
		OFFlowDeleteStrict.Builder fdb = OFFactories.getFactory(OFVersion.OF_13).buildFlowDeleteStrict();
		
		fdb.setMatch(match)
		.setCookie(cookie)
		.setTableId(tableId)
		.setPriority(priority)
		.setBufferId(OFBufferId.NO_BUFFER);
		
		IOFSwitch sw = switchService.getSwitch(switchId);
		
		if(sw!= null){
			sw.write(fdb.build());
		}
	}

	/**
	 * Add security port, called by rest api.
	 */
	@Override
	public boolean addSecurityPort(SwitchPort switchPort) {
		IOFSwitch sw = switchService.getActiveSwitch(switchPort.getSwitchDPID());
		if(sw!=null){
			Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
			mb.setExact(MatchField.IN_PORT, switchPort.getPort());
			
			List<OFInstruction> instructions = new ArrayList<>();
			instructions.add(OFFactories.getFactory(OFVersion.OF_13).instructions().gotoTable(FLOW_TABLE_ID));
			doFlowMod(switchPort.getSwitchDPID(), STATIC_TABLE_ID, mb.build(), null, instructions, BINDING_LAYER_PRIORITY);
		}
		return securityPort.add(switchPort);
	}

	/**
	 * Add delete security service, called rest api.
	 */
	@Override
	public boolean delSecurityPort(SwitchPort switchPort) {
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.IN_PORT, switchPort.getPort());
		doFlowRemove(switchPort.getSwitchDPID(), STATIC_TABLE_ID, mb.build());
		
		return securityPort.remove(switchPort);
	}

	/**
	 * Get security ports.
	 */
	@Override
	public Set<SwitchPort> getSecurityPorts() {
		return securityPort;
	}

	/** 
	 * Get binding entries.
	 */
	@Override
	public List<Binding<?>> getBindings() {
		return manager.getBindings();
	}

	@Override
	public void topologyChanged(List<LDUpdate> linkUpdates) {
		updateQueue.addAll(linkUpdates);
	}

	@Override
	public void linkDiscoveryUpdate(LDUpdate update) {
		updateQueue.add(update);
	}

	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
		updateQueue.addAll(updateList);
	}
	
	@Override
	public Map<DatapathId, Integer> getPortsInBind(){
		return portsInBind;
	}
	
	@Override
	public Map<SwitchPort, Integer> getRank(){
		return rank;
	}

	@Override
	public Set<DatapathId> getStaticSwId() {
		return staticSwId;
	}
	
	@Override
	public Map<SwitchPort, Integer> getHostWithPort(){
		return hostWithPort;
	}
	
	@Override
	public Queue<SwitchPort> getNormalPorts() {
		return normalPorts;
	}
	@Override
	public Queue<SwitchPort> getAbnormalPorts() {
		return abnormalPorts;
	}
	@Override
	public Map<SwitchPort, Integer> getObservePorts() {
		return observePorts;
	}
	
	@Override
	public Queue<SwitchPort> getStaticPorts() {
		return staticPorts;
	}
	
	@Override
	public Queue<SwitchPort> getNonePorts() {
		return nonePorts;
	}
	
	@Override
	public Set<SwitchPort> getPushFlowToSwitchPorts() {
		return pushFlowToSwitchPorts;
	}

	@Override
	public boolean getInit() {
		return alreadyInit;
	}

	@Override
	public void setInit(boolean flag) {
		alreadyInit=flag;
	}

	@Override
	public Set<DatapathId> getNoneSwId() {
		return noneSwId;
	}
	
	
}

