package io.trigger.forge.android.modules.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public abstract class FetchDB extends SQLiteOpenHelper {
 
	protected  SQLiteDatabase db;// = getReadableDatabase();//Apparently, read-only can also be written to
	
	protected final ContentValues values = new ContentValues();
	
	public final static int VERSION = 1;
	
	public FetchDB(Context context, String name) {
		super(context, name, null, VERSION);
		
	}

	protected synchronized void open(){
		db = getReadableDatabase();//Hopefully, this is created and is not null;
	}
	
	
	/*@Override
	public
	synchronized void close(){
		try {
			throw new Exception();
		} catch (Exception e) {
			e.printStackTrace();
		}
		super.close();
	}*/
	
	
	

}
