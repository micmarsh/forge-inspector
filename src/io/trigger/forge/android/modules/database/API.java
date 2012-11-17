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
	
	public static void addnew(final ForgeTask task, @ForgeParam("model") final JSONObject model,
			@ForgeParam("entities") final JSONObject entities){
		initDB();
		try{
			notesDB.addNewNote(model,entities);
			task.success();
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
	
	//Damn it, macros would be awesome here
	public static void changestatus(final ForgeTask task,@ForgeParam("model") JSONObject model,
			@ForgeParam("method") String method,@ForgeParam("entities") JSONObject entities){
		initDB();
		try{
			model.put("sync", method);
			notesDB.updateNoteValues(model,entities);
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}
	
	public static void getnext(final ForgeTask task){
		initDB();
		try{
			
		}catch(Exception e){
			task.error(e);
		}
	}
	
	
}
