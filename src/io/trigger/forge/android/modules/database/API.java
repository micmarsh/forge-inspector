package io.trigger.forge.android.modules.database;

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
	
	public static void put(final ForgeTask task, @ForgeParam("model") final JSONObject model,
			@ForgeParam("entities") final JSONObject entities,@ForgeParam("update") final boolean update){
		initDB();
		try{
			if(update){ 
				notesDB.updateNoteValues(model, entities); 
				task.success();
			}else 
				task.success(notesDB.addNewNote(model,entities));
		}catch(Exception e){
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
	
	public static void wipe(final ForgeTask task){
		initDB();
		try{
			notesDB.reset();
		}catch(Exception e){
			task.error(e);
		}
	}
	
	
}
