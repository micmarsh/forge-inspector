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
	
	public static void put(final ForgeTask task, @ForgeParam("models") final JSONArray models,
			@ForgeParam("entities") final JSONArray entities){
		initDB();
		try{
			int mLength = models.length(),
				eLength = entities.length();
			if(mLength != eLength) 
				throw new Exception("Array lengths not equal");
			for(int i = 0; i < mLength;i++){
				addWithoutInit(task, models.getJSONObject(i), models.getJSONObject(i));
			}
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}
	
	public static void put(final ForgeTask task, @ForgeParam("model") final JSONObject model,
			@ForgeParam("entities") final JSONObject entities){
		initDB();
		try{
			addWithoutInit(task,model,entities);
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}
	
	private static void addWithoutInit(final ForgeTask task, @ForgeParam("model") final JSONObject model,
			@ForgeParam("entities") final JSONObject entities) throws JSONException{
		System.out.println("**********yay model!!!!!!!!!!!!!! "+model.toString());
		
		boolean update;
		if(model.has("localID")){
			final String id = model.getString("localID");
			update = !id.startsWith("c");
		}else//model is something pulled straight in from server
			update = true;
		
		if(update){ 
			notesDB.updateNoteValues(model, entities); 
			task.success();
		}else 
			task.success(notesDB.addNewNote(model,entities));
	}
	
	public static void delete(final ForgeTask task, @ForgeParam("model") final JSONObject model){
		initDB();
		try{
			notesDB.deleteNote(model);
			task.success();
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}
	
	public static void getdirty(final ForgeTask task){
		initDB();
		try{
			task.success(notesDB.getDirtyNotes());
		}catch(Exception e){
			e.printStackTrace();
			task.error(e);
		}
	}
	
	public static void getnext(final ForgeTask task, @ForgeParam("start") final int start,
			@ForgeParam("chunkSize") final int chunkSize){
		initDB();
		try{
			task.success(notesDB.getNextNotes(start, chunkSize));
		}catch(Exception e){
			task.error(e);
		}
	}
	
	public static void getAllTags(final ForgeTask task){
		initDB();
		try{
			task.success(notesDB.getTags());
		}catch(Exception e){
			task.error(e);
		}
	}
	
	public static void fetch(final ForgeTask task, @ForgeParam("tags") JSONArray tags){
		initDB();
		try{
			task.success(notesDB.fetch(tags));
		}catch(Exception e){
			task.error(e);
		}
	}
	
	public static void wipe(final ForgeTask task){
		initDB();
		try{
			notesDB.reset();
		}catch(Exception e){
			task.error(e);
		}
	}
	
	
}
