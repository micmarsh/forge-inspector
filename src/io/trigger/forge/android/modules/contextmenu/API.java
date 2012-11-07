package io.trigger.forge.android.modules.contextmenu;
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

import java.net.URISyntaxException;

import org.json.JSONArray;
import org.json.JSONException;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.view.ContextThemeWrapper;
import android.view.KeyEvent;

public class API {
	
	private static String[] toJavaArray(JSONArray array) throws JSONException{
		String[] toRet = new String[array.length()];
		for(int i = 0; i < toRet.length; i++)
			toRet[i] = array.getString(i);
		return toRet;
	}
			
	public static void show(final ForgeTask task, @ForgeParam("items") final JSONArray JSONItems) throws JSONException{
		final AlertDialog.Builder builder = new AlertDialog.Builder(
				new ContextThemeWrapper(ForgeApp.getActivity(), android.R.style.Theme_Holo));
		final String[] items = toJavaArray(JSONItems);
		builder.setItems(items, new OnClickListener(){
			@Override
			public void onClick(DialogInterface dialog, int which) {
				task.success(items[which]);
			}
		});
		AlertDialog toShow = builder.create();
		toShow.show();
	}
	
}
