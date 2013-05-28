package io.trigger.forge.android.modules.database;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import android.os.AsyncTask;
import android.util.Log;
import android.view.ViewGroup;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;


public class API {
	private static NotesDatabase notesDB;
	
	private static class DatabaseTask extends AsyncTask {
		private Runnable toRun;
		private DatabaseTask(Runnable r){
			toRun = r;
		}
		@Override
		protected Object doInBackground(Object... arg0) {
			if(toRun != null)
				toRun.run();
			return null;
		}
		public static void runTask(Runnable r){
			new DatabaseTask(r).execute();
		}
		
	}

	private static void initDB(){
		Log.e("init notesdb: ","INITING NOTES DB");

		if(notesDB == null){
			Log.e("init notesdb: ","FO REALS");
			notesDB = new NotesDatabase(ForgeApp.getActivity());
		}
	}
	
	public static void createTables(final ForgeTask task, @ForgeParam("schema") final JsonArray schema){
		DatabaseTask.runTask(new Runnable(){
			@Override
			public void run() {
				try{
					NotesDatabase.setQueries(schema);
					initDB();
					notesDB.createTables(schema);
					task.success();
				}catch( Exception e){
					error(task, e);
				}
			}
		});
	}
	
	private static void error(ForgeTask task, Exception e){
		e.printStackTrace();
		task.error(e);
	}
	

	public static void query(final ForgeTask task, @ForgeParam("query") final String query){
		initDB();
		DatabaseTask.runTask(new Runnable(){
			@Override
			public void run() {
				try{
					task.success(notesDB.queryToObjects(query));
				}catch( Exception e){
					error(task, e);
				}
			}
		});
	}
	
	public static void multiQuery(final ForgeTask task, @ForgeParam("queries") final JsonArray queries){
		initDB();
		DatabaseTask.runTask(new Runnable(){
			@Override
			public void run() {
				try{
					notesDB.open();
					JsonArray toRet = new JsonArray();
					for(int i = 0; i < queries.size(); i++){
						JsonElement query = queries.get(i);
						toRet.add(notesDB.queryToObjects(query.getAsString(), false));
					}
					notesDB.close();
					task.success(toRet);
				}catch( Exception e){
					error(task, e);
				}
			}
		});
	}

		
	public static void writeAll(final ForgeTask task, @ForgeParam("queries") final JsonArray queries){
		initDB();
		DatabaseTask.runTask(new Runnable(){
			@Override
			public void run() {
				try{
					notesDB.open();
					JsonArray toRet = new JsonArray();
					for(int i = 0; i < queries.size(); i++){
						JsonObject query = queries.get(i).getAsJsonObject();
						toRet.add(new JsonPrimitive(notesDB.writeQuery(query.get("query").getAsString(), query.get("args").getAsJsonArray())));
					}
					notesDB.close();
					task.success(toRet);
				}catch( Exception e){
					error(task, e);
				}
			}
		});
	}
		
	public static void dropTables(final ForgeTask task, @ForgeParam("tables") final JsonArray tables){
		initDB();
		DatabaseTask.runTask(new Runnable(){
			@Override
			public void run() {
				try{
					notesDB.dropTables(tables);
					task.success();
				}catch( Exception e){
					error(task, e);
				}
			}
		});
	}

}
