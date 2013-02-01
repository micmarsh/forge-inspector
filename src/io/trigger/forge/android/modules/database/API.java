package io.trigger.forge.android.modules.database;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Log;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;


public class API {
	private static NotesDatabase notesDB;

	private static void initDB(){
		Log.e("init notesdb: ","INITING NOTES DB");

		if(notesDB == null){
			Log.e("init notesdb: ","FO REALS");
			notesDB = new NotesDatabase(ForgeApp.getActivity());
		}
	}

	public static void createTables(final ForgeTask task, @ForgeParam("schema") JSONArray schema){
		try{
			NotesDatabase.setQueries(schema);
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}

	public static void entityQuery(final ForgeTask task, @ForgeParam("query") String query
		,@ForgeParam("type") final String type){
		initDB();
		try{						//runs the query, returns a JSONArray of JSONObjects
			task.success(notesDB.queryToEntities(query,type));
		}catch(Exception e){
			task.error(e);
		}
	}


	public static void query(final ForgeTask task, @ForgeParam("query") String query){
		initDB();
		try{					
			task.success(notesDB.queryToNotes(query));
		}catch(Exception e){
			task.error(e);
		}
	}

	
	public static void write(final ForgeTask task, @ForgeParam("query") String query){
		initDB();
		try{
			writeAll(task,new JSONArray().put(query));
			//task.success(notesDB.writeQuery(query));
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
		
	}
	
	public static void writeAll(final ForgeTask task, @ForgeParam("queries") JSONArray queries){
		initDB();
		try{
			notesDB.open();
			JSONArray toRet = new JSONArray();
			for(int i = 0; i < queries.length(); i++){
				JSONObject query = queries.getJSONObject(i);
				toRet.put(notesDB.writeQuery(query.getString("query"), query.getString("text")));
			}
			notesDB.close();
			task.success(toRet);
		}catch(Exception e){
			notesDB.close();
			task.error(e);
		}
	}
		
	public static void wipe(final ForgeTask task){
		initDB();
		try{
			notesDB.reset();
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}


}
