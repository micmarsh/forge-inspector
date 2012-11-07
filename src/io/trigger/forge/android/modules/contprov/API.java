package io.trigger.forge.android.modules.contprov;
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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

public class API {
	
	final static ContentResolver resolver = ForgeApp.getActivity().getContentResolver();
	final static Uri URI = MyContentDescriptor.Categories.CONTENT_URI;

	public static void stickEmployeeInThere(final ForgeTask task,@ForgeParam("name") final String name,
			@ForgeParam("status") final String status){
		try{
			ContentValues cv = new ContentValues();
			cv.put(MyContentDescriptor.Categories.Cols.key_2_catname, name);
			cv.put(MyContentDescriptor.Categories.Cols.key_3_catstatus, status);
			
			resolver.insert(URI, cv);
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}
	
	public static void getSome(final ForgeTask task){
		try{
			task.success(extractNotesFromCursor(resolver.query(URI, null, null,null,null)));
		}catch(Exception e){
			task.error(e);
		}
	}
	
	private static JSONArray extractNotesFromCursor(Cursor c) throws JSONException{
		JSONArray toRet = new JSONArray();
		

		int[] cIndices = new int[]{
				c.getColumnIndex(MyContentDescriptor.Categories.Cols.key_2_catname),
				c.getColumnIndex(MyContentDescriptor.Categories.Cols.key_3_catstatus)
		};
		
		
		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){//Extract note from cursor 
			JSONObject o = new JSONObject();
			o.put("name", c.getString(cIndices[0]));
			o.put("status", c.getString(cIndices[1]));
					//c.getString(cIndices[SERVER_ID]),
			toRet.put(o);
		}
		
		
		return toRet;
	}
	
}