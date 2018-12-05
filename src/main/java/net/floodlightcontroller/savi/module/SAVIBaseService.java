package net.floodlightcontroller.savi.module;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.match.Match;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.ClearIPv4BindingAction;
import net.floodlightcontroller.savi.action.ClearIPv6BindingAction;
import net.floodlightcontroller.savi.action.ClearMacBindingAction;
import net.floodlightcontroller.savi.action.ClearPortBindingAction;
import net.floodlightcontroller.savi.action.ClearSwitchBindingAction;
import net.floodlightcontroller.savi.service.SAVIProviderService;
import net.floodlightcontroller.savi.service.SAVIService;
import net.floodlightcontroller.threadpool.IThreadPoolService;

/**
 * SAVI base service, new module should extends SAVIBaseService. 
 * @author zhouyu
 *
 */
public abstract class SAVIBaseService implements SAVIService, IFloodlightModule{

	static Logger log = LoggerFactory.getLogger(SAVIBaseService.class);
	// Dependent services
	IFloodlightProviderService floodlightProvider;
	IThreadPoolService threadPoolService;
	SAVIProviderService	saviProvider;
	SingletonTask deadlineTimer;
	
	
	@Override
	public void pushActins(List<Action> actions) {
		// TODO Auto-generated method stub
		for(Action action:actions) {
			switch(action.getType()){
			case CLEAR_IPv4_BINDING:
				doClearIPv4BindingAction((ClearIPv4BindingAction)action);
				break;
			case CLEAR_IPv6_BINDING:
				doClearIPv6BindingAction((ClearIPv6BindingAction)action);
				break;
			case CLEAR_PORT_BINDING:
				doClearPortBindingAction((ClearPortBindingAction)action);
				break;
			case CLEAR_SWITCH_BINDING:
				doClearSwitchBindingAction((ClearSwitchBindingAction)action);
				break;
			case CLEAR_MAC_BINDING:
				doClearMacBindingAction((ClearMacBindingAction)action);
				break;
			default:
				break;
			}
		}
	}

	protected void doClearIPv4BindingAction(ClearIPv4BindingAction action){
		
	}
	
	protected void doClearIPv6BindingAction(ClearIPv6BindingAction action){
		
	}
	
	protected void doClearPortBindingAction(ClearPortBindingAction action){
		
	}
	
	protected void doClearSwitchBindingAction(ClearSwitchBindingAction action){
		
	}
	
	protected void doClearMacBindingAction(ClearMacBindingAction action){
		
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> dependencies = new ArrayList<Class<? extends IFloodlightService>>();
		dependencies.add(IFloodlightProviderService.class);
		dependencies.add(IThreadPoolService.class);
		dependencies.add(SAVIProviderService.class);
		return dependencies;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		threadPoolService =context.getServiceImpl(IThreadPoolService.class);
		saviProvider	= context.getServiceImpl(SAVIProviderService.class);
	}

	
	
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		saviProvider.addSAVIService(this);
		
		ScheduledExecutorService ses = threadPoolService.getScheduledExecutor();
		
		deadlineTimer = new SingletonTask(ses, new Runnable() {
			
			@Override
			public void run() {
				// TODO Auto-generated method stub
				checkDeadline();
				deadlineTimer.reschedule(1, TimeUnit.SECONDS);
			}
		});
		deadlineTimer.reschedule(1, TimeUnit.SECONDS);
		
		startUpService();
	}

	@Override
	public abstract boolean match(Ethernet eth);
	
	@Override
	public abstract List<Match> getMatches() ;
	
	@Override
	public abstract RoutingAction process(SwitchPort switchPort, Ethernet eth) ;
	
	public abstract void checkDeadline();
	
	public abstract void startUpService();

}
