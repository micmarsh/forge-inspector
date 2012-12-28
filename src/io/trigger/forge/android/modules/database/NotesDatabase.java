package io.trigger.forge.android.modules.database;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;


public class NotesDatabase extends FetchDB{

	static final String[] TABLE_NAMES = new String[]{"Notes","NoteTag","NoteContacts","NoteEmail","NoteURL"};
	static final int MAIN = 0,
	TAGS = 1,
	CONTACTS = 2,
	EMAILS = 3,
	URLS = 4;


	static final int[] TABLE_ENUMS = {MAIN,TAGS,CONTACTS,EMAILS,URLS};

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


	static final String[] entityStrings = new String[]{"",TAG_COL,CONTACT_COL,EMAIL_COL,URL_COL};


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

	static final String ON_CONFLICT = 	" ON CONFLICT IGNORE";

	static final String SELECT_ALL = "select * from ";


	static String[] initSelectDistinct(){
		String[] toRet = new String[5];
		for(int i = TAGS; i <= URLS;i++)
			toRet[i] = "select distinct "+entityStrings[i]+" from "+TABLE_NAMES[i]+';';
		return toRet;
	}


	static final String[] SELECT_DISTINCT = initSelectDistinct();

	static final String ALL_NOTES_QUERY = SELECT_ALL+TABLE_NAMES[MAIN];

	static final String SELECT_PIECE_PREFIX = "select distinct * from "+TABLE_NAMES[MAIN]+
			 " where "+STATUS_COL+" == "+"'synced' "+
			" order by "+TIME_COL+" desc ";

	static final String DIRTY_NOTES_QUERY = ALL_NOTES_QUERY+" where "+STATUS_COL+" != "+"'synced';";

	public NotesDatabase(Context context) {
		super(context,TABLE_NAMES[MAIN]);
		Log.e("woot woot","called constructor!");
		open();//won't be created until we do this!
		close();
	}


	public void onCreate(SQLiteDatabase db) {
		create_tables(db);
	}

	private void create_tables(SQLiteDatabase db){
		Log.e("create tables","create tables called");
		int i = 0;
		for(String name : TABLE_NAMES){
			db.execSQL(CREATE + name + ' '+SCHEMA[i]+';');
			i++;
		}

		this.db = db;
	}



	private void drop_tables(){
		for(String name:TABLE_NAMES)db.execSQL("drop table "+name+';');
	}

	public synchronized void reset(){
		open();
		drop_tables();
		create_tables(db);
		close();
	}


 	public void onUpgrade(SQLiteDatabase arg0, int arg1, int arg2) {
		//LULZ
	}

 	private void extractAndSetNoteVals(JSONObject model) throws JSONException{
 		setNoteVals(model.getString("text"),
				model.getString("html"),
				model.getString("id"),
				model.getString("lastModified"),
				model.getString("sync"));
 	}

 	public synchronized JSONArray queryToTags(String query){
		return queryToEntities(query,"tag");
	}

	public synchronized JSONArray queryToEntities(String query, String type){//"tag" "contact" "email" or "url"
		open();
		Cursor c = db.rawQuery(query, null);
		JSONArray entities = new JSONArray();

		int col = c.getColumnIndex(type);

		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){
			entities.put(c.getString(col));
		}

		c.close();
		close();
		return entities;
	}

	//Takes a string, returns a JSONArray of JSONObjects
	public synchronized JSONArray queryToNotes(String query) throws JSONException{
		open();
		Cursor c = db.rawQuery(query, null);//the actual querying happens
		JSONArray notes = extractNotesFromCursor(c);
		c.close();
		close();
		return notes;
	}

	public synchronized JSONArray writeQuery(String query, String method){
		JSONArray toRet = new JSONArray();
		db.rawQuery(query, null);
		toRet.put(db.rawQuery("SELECT last_insert_rowid()", null));
		return toRet;
	}
 	
	public synchronized String addNewNote(JSONObject model, JSONObject entities) throws JSONException{
		if( !db.isOpen() )open();
		extractAndSetNoteVals(model);
		String id = ""+db.insertWithOnConflict(TABLE_NAMES[MAIN],null,values,SQLiteDatabase.CONFLICT_IGNORE);
		for(int i = TAGS; i <= URLS; i++) addEntities(entities.getJSONArray(entityStrings[i]),id,i);
		if(db.isOpen() && !db.inTransaction())close();
		return id;
	}

	public synchronized String updateNoteValues(JSONObject model, JSONObject entities) throws JSONException{
		open();
		extractAndSetNoteVals(model);
		String id = getLocalID(model);
		clearNote(id,true);
		db.update(TABLE_NAMES[MAIN], values, LOC_COL+"='"+id+"'", null);
		for(int i = TAGS; i <= URLS; i++) addEntities(entities.getJSONArray(entityStrings[i]),id,i);
		close();
		return id;
	}

	private String getLocalID(JSONObject model) throws JSONException{
		if(model.has("localID")) return model.getString("localID");//If this model doesn't have a localID, it must be a direct
		else return getID(model.getString("id"),true);// translation of a server note, so we can look up its localID
	}

	private void addEntities(JSONArray array,String noteID, int type) throws JSONException{
		int length = array.length();
		for(int i = 0; i < length; i++){
			setEntityVal(noteID,array.getString(i).toLowerCase(),type);
			db.insert(TABLE_NAMES[type], null, values);
		}
	}

	private void setNoteVals(String text, String htmlText,String server_id,
			String timestamp,String status){
		values.clear();
		values.put(TEXT_COL,text);
		values.put(HTML_COL,htmlText);
		values.put(SERV_COL,server_id);
		values.put(TIME_COL,timestamp);
		values.put(STATUS_COL, status);
	}


	private void setEntityVal(String id, String entityText,int type){
		values.clear();
		values.put(LOC_COL,id);
		values.put(entityStrings[type], entityText);
	}

	public JSONArray getDirtyNotes() throws JSONException{
			JSONArray toRet = queryToNotes(DIRTY_NOTES_QUERY);
			return toRet;
	}

	public synchronized JSONArray getNextNotes(int start, int chunkSize) throws JSONException{
		JSONArray toRet = queryToNotes(getNextQuery(start,chunkSize));
		return toRet;

	}

	private String getNextQuery(int start, int chunkSize){
		String toRet = SELECT_PIECE_PREFIX +" limit "+start+','+chunkSize;
		return toRet;
	}

	
	//Takes a Cursor (the "raw" result of query in android) and converts it the a JSONArray of JSONObjects
	private JSONArray extractNotesFromCursor(Cursor c) throws JSONException{
		JSONArray toRet = new JSONArray();

		int[] cIndices = new int[NOTE_COLS.length];
		for(int i = 0; i < NOTE_COLS.length;i++)cIndices[i] = c.getColumnIndex(NOTE_COLS[i]);//Find the indices of each column in the curso

		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){//Extract note from cursor
			toRet.put(new JSONObject()
						.put("text",c.getString(cIndices[TEXT]))
						.put("html",c.getString(cIndices[HTML]))
						.put("localID",c.getString(cIndices[LOCAL_ID]))
						.put("lastModified",c.getString(cIndices[TIMESTAMP]))
						.put("id", c.getString(cIndices[SERVER_ID]))
						.put("sync", c.getString(cIndices[STATUS])));
		}
		return toRet;
	}

	public synchronized void deleteNote(JSONObject note) throws JSONException{
		open();
		clearNote(note.has("localID")?note.getString("localID"):
			getID(note.getString("id"),true),false);
		close();
	}

	private void clearNote(String id,boolean justEntities){
		final String whereClause = LOC_COL+"='"+id+'\'';;
		//If just clearing out entities (as part of an edit call), start clearing things out at the "TAGS" enum
		for(int i = justEntities?TAGS:MAIN; i < TABLE_ENUMS.length;i++)
			db.delete(TABLE_NAMES[TABLE_ENUMS[i]], whereClause, null);
	}

	//Database must be open for this to work out
	private  synchronized String getID(String id, boolean getLoc){
		String selectID = (getLoc?LOC_COL:SERV_COL) ;
		String query = "select "+
				selectID+
				" from "+TABLE_NAMES[MAIN]+" where "+
				(getLoc?SERV_COL:LOC_COL)+
				"=" +
				(getLoc?"'":"")+id+
				(getLoc?"'":"");
		Cursor c = db.rawQuery(query,null);//get the needed id, if it exists
		if(!c.moveToFirst()){c.close();return null;}//if nothing found, nothing to return
		int col = c.getColumnIndex(selectID);
		String toRet = (col == -1?null:
			(getLoc?c.getInt(col)+""://the ids are different data types
				c.getString(col)));
		c.close();
		return toRet;
	}



	private JSONArray getEntities(int type){
		if(!db.isOpen())open();
		Cursor c = db.rawQuery(SELECT_DISTINCT[type],null);
		JSONArray entities = new JSONArray();

		int col = c.getColumnIndex(entityStrings[type]);

		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){
			entities.put(c.getString(col));
		}

		c.close();
		close();
		return entities;


	}


	public synchronized JSONArray getTags() {
		return getEntities(TAGS);
	}




	private String buildFetchQuery(JSONArray tags,boolean noteByTag) throws JSONException{
		StringBuilder query = new StringBuilder("");
		int length = tags.length();
		for(int i = 0; i < length; i++){
			String s = tags.getString(i);
			if(!query.toString().equals(""))
				query.append(noteByTag?" intersect ":" union ");
			query.append("select distinct "+
				(noteByTag?LOC_COL:TAG_COL)
				+" from "+TABLE_NAMES[TAGS]
					+" where "+
				(noteByTag?TAG_COL:LOC_COL)
				+" == "+'\''+s+'\'');//switch the two "COL"'s!
		}
		Log.e("NotesDatabase query getSetBySet",query.toString());
		return query.toString()+';';
	}

	private String[] getSetBySet(JSONArray set,boolean noteByTag) throws JSONException{

		Cursor c = db.rawQuery(buildFetchQuery(set,noteByTag),null);//this would need to be changed (see above)

		String[] toRet = new String[c.getCount()];
		System.out.println("amount returned: "+c.getCount());
		int col = c.getColumnIndex(noteByTag?LOC_COL:TAG_COL);//this need to be TAG_COL

		int i = 0;
		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){
			toRet[i] = c.getString(col);
			i++;
		}

		c.close();
		return toRet;
	}

	private synchronized String[] getIDs(JSONArray tags) throws JSONException{
		return getSetBySet(tags,true);
	}

	public synchronized JSONObject getNote(String id) throws JSONException{

		String loc_id = id.length() > 20?getID(id,true):id;//translates id to local if not already

		if(loc_id == null) return null;

		if(!db.isOpen())open();

		String query = SELECT_ALL+TABLE_NAMES[MAIN]+" where "+LOC_COL+"="+loc_id;

		Cursor c = db.rawQuery(query, null);

		JSONObject toRet = extractNotesFromCursor(c).getJSONObject(0);//?????

		c.close();
		if(db.isOpen())close();

		return toRet;

	}

	public synchronized JSONArray fetch(JSONArray tags) throws JSONException {

		open();

		String[] ids = getIDs(tags);

		JSONArray toRet = new JSONArray();

		for(String id:ids){Log.e("omg note id",id);toRet.put(getNote(id));}

		close();

		return toRet;
	}


/*	public synchronized Note addNewNote(String text,String server_id,String timestamp  ){
		if(!db.isOpen() )open();

		String htmlText = Parser.addHtml(text);

		setNoteVals(text,htmlText,server_id,timestamp);
		String id = ""+db.insertWithOnConflict(TABLE_NAMES[MAIN],null,values,SQLiteDatabase.CONFLICT_IGNORE);
		addEntities(text,id);

		if(db.isOpen() && !db.inTransaction())close();

		return new Note(text,htmlText,id,server_id,timestamp);
	}







	private ArrayList<String> getEntity(String note,int type){
		ArrayList<String> toRet = null;

		switch(type){
		case TAGS:
			toRet = Parser.getAllTags(note);
			break;
		case EMAILS:
			toRet = Parser.getEmails(note);
			break;
		case URLS:
			toRet = Parser.getUrls(note);
			break;
		}

		return toRet;
	}



	private String[] getTagsByIDs(ArrayList<String> ids){
		return getSetBySet(ids,false);
	}

	private Note[] extractNotesFromCursor(Cursor c){
		Note[] toRet = new Note[c.getCount()];


		int[] cIndices = new int[NOTE_COLS.length];
		for(int i = 0; i < NOTE_COLS.length;i++)cIndices[i] = c.getColumnIndex(NOTE_COLS[i]);//Find the indices of each column in the curso


		{
		int i = 0;
		for(c.moveToFirst();!c.isAfterLast();c.moveToNext()){//Extract note from cursor
			toRet[i] = new Note(c.getString(cIndices[TEXT]),
					c.getString(cIndices[HTML]),
					c.getString(cIndices[LOCAL_ID]),
					c.getString(cIndices[SERVER_ID]),
					c.getString(cIndices[TIMESTAMP]));
			i++;
		}
		}

		return toRet;
	}



	//ArrayList<Note> leftOver = new ArrayList<Note>();




	public synchronized Note[] getAllNotes() {
	//	open();
	//	Cursor c = db.rawQuery(ALL_NOTES_QUERY,null);//Database query

		Note[] toRet = new Note[0];//extractNotesFromCursor(c);

	//	close();
		return toRet;

	}

	public static final int CHUNK_SIZE = 25;



	int cur_index = 0;





	public void resetNextNotes(){
		//CommonFunctions.showStackTrace();
		cur_index = 0;
	}

	public int getCurIndex(){
		return cur_index;
	}

	public String getName() {
		return "yourmum";
	}






	public void updateNote(Note note, String newText) {
		updateNote(note,newText,note.getServerID());
	}


	public void updateNote(Note note,String newText,String server_id){
		updateNoteValues(note,newText,server_id,null);
	}




	public void updateNote(Note note, String newText, String server_id, String timestamp) {
		Log.e("NotesDatabase updateNotes",""+note);
		updateNoteValues(note, newText, server_id, timestamp);

	}







	public synchronized String[] getAssocTagsList(String[] tags) {
		return getAssocTags(new ArrayList<String>(Arrays.asList(tags)));
	}


	private synchronized String[] getAssocTags(ArrayList<String> tags){
		open();

		String[] notes = getIDs(tags);

		String[] toRet = getTagsByIDs(new ArrayList<String>(Arrays.asList(notes)));
		close();
		return toRet;

	}




	public synchronized String[] getAssocTags(String tag) {
		ArrayList<String> asList = new ArrayList<String>();
		asList.add(tag);

		return getAssocTags(asList);
	}



	public synchronized String getLocID(String server_id){
		return getID(server_id,true);
	}


	public synchronized String getServID(String local_id){
		return getID(local_id,false);

	}






	public synchronized Note[] getUnsynced() {
		final String unsyncedQuery = SELECT_ALL +TABLE_NAMES[MAIN]+" where "+SERV_COL+"='NULL' ";
		return queryToNotes(unsyncedQuery);
	}


	public synchronized Note[] search(String query) {
		final String searchQuery = SELECT_ALL+TABLE_NAMES[MAIN]+" where "+TEXT_COL+" like '%"+query+"%'";
		return queryToNotes(searchQuery);

	}
*/
}

