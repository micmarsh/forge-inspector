package io.trigger.forge.android.modules.contprov;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class MyDatabase extends SQLiteOpenHelper {
	 
    private static final String DATABASE_NAME = "mydatabase.db";
    private static final int DATABASE_VERSION = 1;
 
    // custom constructor
    public MyDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        // TODO Auto-generated constructor stub
    }
 
    @Override
    public void onCreate(SQLiteDatabase db) {
        // TODO Auto-generated method stub
 
        // creating tables categories
        db.execSQL("CREATE TABLE " + MyContentDescriptor.Categories.TABLE_NAME+ " ( "+
                 MyContentDescriptor.Categories.Cols.cat_id+ " INTEGER PRIMARY KEY AUTOINCREMENT,"+
                 MyContentDescriptor.Categories.Cols.key_2_catname    + " TEXT NOT NULL," +
                 MyContentDescriptor.Categories.Cols.key_3_catstatus + " TEXT," +
                "UNIQUE (" + 
                MyContentDescriptor.Categories.Cols.cat_id + 
            ") ON CONFLICT REPLACE)"
                );
 
    }
    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // TODO Auto-generated method stub
         if(oldVersion < newVersion){
                db.execSQL("DROP TABLE IF EXISTS " + MyContentDescriptor.Categories.TABLE_NAME);
 
            }
    }
}