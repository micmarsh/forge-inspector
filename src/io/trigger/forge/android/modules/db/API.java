package io.trigger.forge.android.modules.db;

import org.json.JSONObject;

import io.trigger.forge.android.core.ForgeApp;
import io.trigger.forge.android.core.ForgeParam;
import io.trigger.forge.android.core.ForgeTask;


public class API {
	private static NotesDatabase notesDB;
	
	private static void initDB(){
		if(notesDB == null)
			notesDB = new NotesDatabase(ForgeApp.getActivity());
	}
	
	@SuppressWarnings("unused")
	private static void addnew(final ForgeTask task, @ForgeParam("model") JSONObject model, @ForgeParam("entities") JSONObject entities){
		initDB();
		try{
			notesDB.addNewNote(model, entities);
			task.success();
		}catch(Exception e){
			task.error(e);
		}
	}
	
	
	
}
