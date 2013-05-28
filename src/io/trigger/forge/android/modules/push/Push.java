package io.trigger.forge.android.modules.push;

import io.trigger.forge.android.core.ForgeTask;

import java.util.Map;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.Notification;
import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.kinvey.android.Client;
import com.kinvey.android.push.PushOptions;
import com.kinvey.android.push.UrbanAirshipPushOptions;
import com.kinvey.java.core.KinveyClientCallback;
import com.urbanairship.push.PushNotificationBuilder;

public class Push {
	public static class Settings {
		public final int PUSH_KEY = 0, PUSH_SECRET = 1;
		public final Activity activity;
		public final String pushKey, pushSecret;
		public final Client kinveyClient;
		public Settings (Activity activity, String[] keys, Client kinveyClient){
			this.activity = activity;
			pushKey = keys[PUSH_KEY];
			pushSecret = keys[PUSH_SECRET];
			this.kinveyClient = kinveyClient;
			
		}
	}
	private static Settings settings;
	public static void initializePush(Settings settings, ForgeTask task){
		Push.settings = settings;
		initializeClient(false);
		registerUser(task);
	}
	
	private static void registerUser(ForgeTask task) {
		initializeClient(true);
		addKinveyCallback(task);
	}
	
	private static void initializeClient (boolean inProduction) {
		UrbanAirshipPushOptions options = (UrbanAirshipPushOptions) 
				settings.kinveyClient
				.push().getPushOptions(settings.pushKey, settings.pushSecret, inProduction);
		settings.kinveyClient.push().initialize(options, settings.activity.getApplication());
		settings.kinveyClient.push().setNotificationBuilder(new PushNotificationBuilder(){

			@Override
			public Notification buildNotification(String arg0,
					Map<String, String> arg1) {
				Log.e(arg0, "" + arg1);
				return null;
			}

			@Override
			public int getNextId(String arg0, Map<String, String> arg1) {
				// TODO Auto-generated method stub
				return 0;
			}
		});
	}

	private static void addKinveyCallback(final ForgeTask task) {
		settings.kinveyClient.user().registerPush(new KinveyClientCallback<Void>() {
		    @Override
		    public void onFailure(Throwable e)  {
		    	e.printStackTrace();
		    	task.error(e);
		    }
		    @Override
		    public void onSuccess(final Void v) {
		    	settings.activity.runOnUiThread( new Runnable(){
					@Override
					public void run() {
				    	Log.e("omg pushed", "u got pushed");
				    	Log.e("a void:", v + "");
				    	Toast.makeText(settings.activity, "Yay a push", 4000).show();
				    	new AlertDialog.Builder(settings.activity)
				    			.setTitle("WHAT")
				    			.setMessage("POOSHED 2 U")
				    			.show();
						
					}
		    	});
		    }
		});
	}

	
}

