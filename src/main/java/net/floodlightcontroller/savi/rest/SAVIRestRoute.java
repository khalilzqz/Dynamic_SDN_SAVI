package net.floodlightcontroller.savi.rest;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class SAVIRestRoute implements RestletRoutable{
	protected static final String CONVERT_TO_STATIC="static";
	protected static final String CONVERT_TO_DYNAMIC="dynamic";
	protected static final String CONVERT_TO_NONE="none";
	protected static final String DPID_STR = "dpid";
	/**
	 * Restlet route.
	 */
	@Override
	public Restlet getRestlet(Context context) {
		// TODO Auto-generated method stub
        Router router = new Router(context);
		router.attach("/config", SAVIRest.class);
		router.attach("/flow",FlowResource.class);
		router.attach("/change/static/{"+DPID_STR+"}",ChangeTableResource.class);
		router.attach("/change/dynamic/{"+DPID_STR+"}",ChangeTableResource.class);
		router.attach("/change/none/{"+DPID_STR+"}",ChangeTableResource.class);
		return router;
	}

	/**
	 * Base path.
	 */
	@Override
	public String basePath() {
		// TODO Auto-generated method stub
		return "/savi";
	}
}
