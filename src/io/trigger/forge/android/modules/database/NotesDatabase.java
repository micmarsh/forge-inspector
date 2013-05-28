package io.trigger.forge.android.modules.database;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import android.annotation.SuppressLint;
import android.content.Context;
import android.database.Cursor;
import android.database.CursorIndexOutOfBoundsException;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;


public class NotesDatabase extends FetchDB{

	//static final String[] TABLE_NAMES = new String[]{"Notes","NoteTag","NoteContacts","NoteEmail","NoteURL"};
	static final int MAIN = 0,
	TAGS = 1,
	CONTACTS = 2,
	EMAILS = 3,
	URLS = 4;

	static final String CREATE = "CREATE TABLE ";

	static final String TEXT_COL = "text",
	HTML_COL = "html",
	LOC_COL = "local_id",
	SERV_COL = "server_id",
	TIME_COL = "last_updated",
	STATUS_COL = "sync_status",
	TAG_COL = "tag",
	CONTACT_COL = "contact",
	EMAIL_COL = "email",
	URL_COL = "url";


	static final String LOC_ID = LOC_COL+" INTEGER PRIMARY KEY ";

	static final String[] NOTE_COLS = new String[]{TEXT_COL,HTML_COL,LOC_COL,SERV_COL,TIME_COL,STATUS_COL};

	static final int TEXT = 0,
			HTML = 1,
			LOCAL_ID = 2,
			SERVER_ID = 3,
			TIMESTAMP = 4,
			STATUS = 5;

	static final String[] SCHEMA = new String[]{'('+TEXT_COL+" TEXT, "+HTML_COL+" TEXT,"+LOC_ID+", "
									+SERV_COL+" TEXT UNIQUE, "+TIME_COL+" TEXT, "+STATUS_COL+" TEXT )",
		'('+LOC_COL+", "+TAG_COL+" TEXT)",
		'('+LOC_COL+", "+CONTACT_COL+" TEXT)",
		'('+LOC_COL+','+EMAIL_COL+" TEXT)",
		'('+LOC_COL+','+URL_COL+" TEXT)",

	};


	//In all likelihood, none of this^ shit is needed
	
	private static String[] CREATE_TABLE_QUERIES = null;
	private static String[] TABLE_NAMES = null;
	
	public static void setQueries(JsonArray schema) {
		int length = schema.size();//schema.length();
		TABLE_NAMES = new String[length];
		CREATE_TABLE_QUERIES = new String[length];
		for(int i = 0; i < length; i++){
			JsonObject info = schema.get(i).getAsJsonObject();//.getJSONObject(i);
			TABLE_NAMES[i] = info.get("name").getAsString();
			CREATE_TABLE_QUERIES[i] = "CREATE TABLE "+info.get("name").getAsString()+" "+info.get("schema").getAsString();
			Log.e("tables init'ed", CREATE_TABLE_QUERIES[i]);
		}
	}
	
	public NotesDatabase(Context context) {
		super(context,"Main");
		Log.e("woot woot","called constructor!");
		open();//won't be created until we do this!
		close();
	}


	public void onCreate(SQLiteDatabase db) {
		create_tables(db);
	}
	
	public void createTables(JsonArray schema) throws SQLException{
		open();
		Log.e("create tables","non-fresh create tables called");
		for(int i = 0; i < schema.size(); i++){
			JsonObject table = schema.get(i).getAsJsonObject();
			db.execSQL("create table if not exists "+table.get("name").getAsString()+
					' '+table.get("schema").getAsString());
		}
		close();
	}

	private void create_tables(SQLiteDatabase db){
		Log.e("create tables","create tables called");
		for(String name : CREATE_TABLE_QUERIES) db.execSQL(name+';');
		this.db = db;
	}



	public  void dropTables(JsonArray tables) throws SQLException {
		open();
		for(String name:toArray(tables))db.execSQL("drop table "+name+';');
		close();
	}

	

 	public void onUpgrade(SQLiteDatabase arg0, int arg1, int arg2) {
		//LULZ
	}


 	public synchronized JsonArray queryToObjects(String query) {
 		return queryToObjects(query, true);
 	}
	
	//Takes a string, returns a JSONArray of JSONObjects
	public synchronized JsonArray queryToObjects(String query, boolean atomic) {
		if(atomic) open();
		Cursor c = db.rawQuery(query, null);//the actual querying happens
		Log.e("Cursor length: ",""+c.getCount());
		JsonArray notes = cursorToArray(c);
		c.close();
		if(atomic) close();
		return notes;
	}
	
	private String[] toArray(JsonArray tables) {
		String[] results = new String[tables.size()];
		for(int i = 0; i < results.length; i++) results[i] = tables.get(i).getAsString();
		return results;
		
	}

	public synchronized int writeQuery(String query, JsonArray args) throws SQLException {
		db.execSQL(query,toArray(args));
		
		String column= "last_insert_rowid()";
		
		Cursor c = db.rawQuery("SELECT "+column+" from Notes", null);
										//this^ is the worst shit ever

		c.moveToFirst();
		int result = 0;
		try{
			result = c.getInt(c.getColumnIndex(column));
		}catch(CursorIndexOutOfBoundsException e){
			//TODO: something, maybe	
		}
		
		c.close();
		return result;
	}
	
	@SuppressLint("NewApi")
	private JsonPrimitive postHoneyComb(Cursor c, int index) {
		switch(c.getType(index)){
			case Cursor.FIELD_TYPE_FLOAT:
				return new JsonPrimitive(c.getFloat(index));
			case Cursor.FIELD_TYPE_INTEGER:
				return new JsonPrimitive(c.getInt(index));
			case Cursor.FIELD_TYPE_STRING:
				return new JsonPrimitive(c.getString(index));
			case Cursor.FIELD_TYPE_NULL:
			default:
				return null;
		}
	}
	//only ever going to be an int or a string, in our case
	private JsonPrimitive preHoneyComb(Cursor c, int index) {
		//lol the worst control flow
		System.out.println("prehoneycomblulz");
		JsonPrimitive result = null;
		try{
			System.out.println("trying getString");
			result = new JsonPrimitive(c.getString(index));
		}catch(Exception e){
			System.out.println("trying getInt");
			result =  new JsonPrimitive(c.getInt(index));
		}
		System.out.println("returning "+result);
		return result;
			
	}
	
	private JsonPrimitive get(Cursor c, int index) { 	
		JsonPrimitive result = null;
		System.out.println("oh shit a get");
		try {
			result = postHoneyComb(c, index);
		}catch(java.lang.NoSuchMethodError e){
			result = preHoneyComb(c, index);
		}
		return result;	
	}
	
	private JsonArray cursorToArray(Cursor c) {
		final String[] columnNames = c.getColumnNames();
		JsonArray results = new JsonArray();
		
		Log.e("cursor", "All the columns: "+columnNames.length);
		
		for (c.moveToFirst();!c.isAfterLast();c.moveToNext()){
			JsonObject object = new JsonObject();
			for(String name : columnNames){
				int index = c.getColumnIndex(name);
				object.add(name, get(c, index));
			}
			results.add(object);
		}
		
		return results;
	}

}

	