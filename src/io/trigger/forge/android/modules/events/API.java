package io.trigger.forge.android.modules.events;


import android.os.SystemClock;
import android.view.MotionEvent;
import android.webkit.WebView;
import io.trigger.forge.android.core.ForgeActivity;
import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;

public class API {
	
	public static void touch(final ForgeTask task,
			@ForgeParam("x") final int x, @ForgeParam("y") final int y){
		ForgeActivity activity = ForgeApp.getActivity();
		final WebView webView = activity.webView;
		activity.runOnUiThread(new Runnable() {
        	public void run() {
	        		webView.dispatchTouchEvent(MotionEvent.obtain(
	        				SystemClock.uptimeMillis(),
	        				SystemClock.uptimeMillis(), 
	        				MotionEvent.ACTION_DOWN, 
	        				x,
	        				y,
	        				0)
	        		);
	        		webView.dispatchTouchEvent(MotionEvent.obtain(
	        				SystemClock.uptimeMillis(), 
	        				SystemClock.uptimeMillis(), 
	        				MotionEvent.ACTION_UP, 
	        				x,
	        				y,
	        				0)
	        		);
				task.success();
        	}
	
		});
	}
}
