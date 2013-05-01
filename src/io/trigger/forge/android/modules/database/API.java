package io.trigger.forge.android.modules.database;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import android.os.AsyncTask;
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
	
	public static void createTables(final ForgeTask task, @ForgeParam("schema") JsonArray schema){
		try{
			NotesDatabase.setQueries(schema);
			initDB();
			notesDB.createTables(schema);
			task.success();
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}


	public static void query(final ForgeTask task, @ForgeParam("query") String query){
		initDB();
		try{					
			Log.e("query", ""+query);
			task.success(notesDB.queryToObjects(query));
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}
	
	public static void multiQuery(final ForgeTask task, @ForgeParam("queries") JsonArray queries){
		initDB();
		try{
			notesDB.open();
			JsonArray toRet = new JsonArray();
			for(int i = 0; i < queries.size(); i++){
				String query = queries.get(i).getAsString();
				toRet.add(notesDB.queryToObjects(query, false));
			}
			notesDB.close();
			task.success(toRet);
		}catch(Exception e){
			
		}
	}

		
	public static void writeAll(final ForgeTask task, @ForgeParam("queries") JsonArray queries){
		initDB();
		try{
			notesDB.open();
			JsonArray toRet = new JsonArray();
			for(int i = 0; i < queries.size(); i++){
				JsonObject query = queries.get(i).getAsJsonObject();
				toRet.add(new JsonPrimitive(notesDB.writeQuery(query.get("query").getAsString(), query.get("args").getAsJsonArray())));
			}
			notesDB.close();
			task.success(toRet);
		}catch(Exception e){
			notesDB.close();
			task.error(e);
		}
	}
		
	public static void dropTables(final ForgeTask task, @ForgeParam("tables") JsonArray tables){
		initDB();
		try{
			notesDB.dropTables(tables);
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}


}
