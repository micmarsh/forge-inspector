package io.trigger.forge.android.modules.contprov;


import io.trigger.forge.android.core.ForgeContentProvider;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.util.Log;

public class MyContentProvider extends ForgeContentProvider {
	 
    private MyDatabase mydb;
    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        Context ctx = getContext();
        mydb = new MyDatabase(ctx);
        return (mydb == null) ? false : true;
    }
 
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
         SQLiteDatabase db = mydb.getWritableDatabase();
         int token = MyContentDescriptor.URI_MATCHER.match(uri);
         int count=0;
         
         switch(token){
         case MyContentDescriptor.Categories.CAT_PATH_TOKEN:
            count= db.delete(MyContentDescriptor.Categories.TABLE_NAME, selection, selectionArgs);
             break;
         }
        getContext().getContentResolver().notifyChange(uri, null);
        return count;
   
    }
 
    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub // returning self defined mime types
        // to be used by other applications if any
        return null;
    }
 
    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
 
        Log.d("sohail", "inside insert");
        SQLiteDatabase db = mydb.getWritableDatabase();
 
        int token = MyContentDescriptor.URI_MATCHER.match(uri);
        switch (token) {
        case MyContentDescriptor.Categories.CAT_PATH_TOKEN: // uri is of
                                                            // categories table
            Log.d("sohail", "matched uri is CAT_PATH_TOKEN:" + uri.toString());
            long id = db.insert(MyContentDescriptor.Categories.TABLE_NAME,
                    null, values);
            // notifying change to content observers
            getContext().getContentResolver().notifyChange(uri, null);
            return MyContentDescriptor.Categories.CONTENT_URI.buildUpon()
                    .appendPath(String.valueOf(id)).build();
 
        default:
            throw new UnsupportedOperationException("URI: " + uri
                    + " not supported.");
        }
    }
 
    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        // TODO Auto-generated method stub
        Log.d("sohail", "query called");
        SQLiteDatabase db = mydb.getReadableDatabase();
        SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
        Cursor c;
        int token = MyContentDescriptor.URI_MATCHER.match(uri);
 
        switch (token) {
 
        case MyContentDescriptor.Categories.CAT_PATH_TOKEN:
            Log.d("sohail", "matched uri is CAT_PATH_TOKEN:" + uri.toString());
            queryBuilder.setTables(MyContentDescriptor.Categories.TABLE_NAME);
            c = queryBuilder.query(db, projection, selection, selectionArgs,
                    null, null, sortOrder);
            return c;
 
        case MyContentDescriptor.Categories.CAT_PATH_FOR_ID_TOKEN:
            Log.d("sohail", "matched uri is CAT_PATH_TOKEN:" + uri.toString());
            queryBuilder.setTables(MyContentDescriptor.Categories.TABLE_NAME);
            queryBuilder.appendWhere(MyContentDescriptor.Categories.Cols.cat_id
                    + "=" + uri.getLastPathSegment());
            c = queryBuilder.query(db, projection, selection, selectionArgs,
                    null, null, sortOrder);
            return c;
 
       default:
            Log.d("sohail", "no URI MATCHED");
            return null;
        }
 
    }
 
    @Override
    public int update(Uri uri, ContentValues values, String selection,
            String[] selectionArgs) {
        // TODO Auto-generated method stub
         SQLiteDatabase db = mydb.getWritableDatabase();
         int token = MyContentDescriptor.URI_MATCHER.match(uri);
         int count=0;
         
         switch(token){
         case MyContentDescriptor.Categories.CAT_PATH_TOKEN:
            count= db.update(MyContentDescriptor.Categories.TABLE_NAME,values, selection, selectionArgs);
             break;
            }
         
        getContext().getContentResolver().notifyChange(uri, null);
        return count;
         
    }
 
}