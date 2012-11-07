package io.trigger.forge.android.modules.keyboard;
/*
Copyright 2012 Fetchnotes,Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
  */

import io.trigger.forge.android.core.ForgeActivity;
import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;

import android.content.Context;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.InputMethodManager;

public class API {
	public static KeyCharacterMap map = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD);

	public static void typestring(final ForgeTask task, @ForgeParam("input") final String input){
		final ForgeActivity activity = ForgeApp.getActivity();
		final KeyEvent[] events = map.getEvents(input.toCharArray());
		InputMethodManager mgr = getKeyboard(activity);
		mgr.displayCompletions(activity.webView, null);
		
		activity.runOnUiThread(new Runnable(){
			@Override
			public void run() {
				for(KeyEvent e : events)
					activity.dispatchKeyEvent(e);
				task.success();
			}
		});

	}
	
	public static void show(final ForgeTask task){
		ForgeActivity activity = ForgeApp.getActivity();
		InputMethodManager mgr = getKeyboard(activity);
        mgr.showSoftInput(activity.webView, InputMethodManager.SHOW_IMPLICIT);
	}
	
	private static final String FOCUS_FUNCTION = "$('#search-notes').focus();console.log('poop');" +
			"$('#search-notes').caretTo(5)";//"Fetch.editNote.textarea.focus()";
	
	public static void focus(final ForgeTask task){
		final ForgeActivity activity = ForgeApp.getActivity();
		activity.runOnUiThread(new Runnable(){
			@Override
			public void run() {
				activity.webView.requestFocus(View.FOCUS_DOWN);
				activity.webView.loadUrl("javascript:"+FOCUS_FUNCTION);
				show(task);
				task.success();
			}
		});
	}
	private static InputMethodManager getKeyboard(ForgeActivity activity){
		return (InputMethodManager) activity.getSystemService(Context.INPUT_METHOD_SERVICE);
	}
}