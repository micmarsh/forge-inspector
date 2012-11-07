package io.trigger.forge.android.modules.contprov;

import android.content.UriMatcher;
import android.net.Uri;
import android.provider.BaseColumns;



public class MyContentDescriptor {
	 
    public static final String AUTHORITY = "sohail.aziz.mycontentprovider";
    private static final Uri BASE_URI = Uri.parse("content://" + AUTHORITY);
    public static final UriMatcher URI_MATCHER = buildUriMatcher();
 
    private static UriMatcher buildUriMatcher() {
 
        // TODO Auto-generated method stub
 
        final UriMatcher matcher = new UriMatcher(UriMatcher.NO_MATCH);
 
        // have to add tables uri here
 
        final String authority = AUTHORITY;
 
        //adding category Uris
 
        matcher.addURI(authority, Categories.CAT_PATH, Categories.CAT_PATH_TOKEN);
 
        matcher.addURI(authority, Categories.CAT_PATH_FOR_ID,Categories.CAT_PATH_FOR_ID_TOKEN);
      
        return matcher;
 
    }
    public static class Categories {
 
        // an identifying name for entity
 
        public static final String TABLE_NAME = "categories"; 
        // the toke value are used to register path in matcher (see above)
        public static final String CAT_PATH = "categories";
        public static final int CAT_PATH_TOKEN = 100;
 
        public static final String CAT_PATH_FOR_ID = "categories/*";
        public static final int CAT_PATH_FOR_ID_TOKEN = 200;
 
        public static final Uri CONTENT_URI = BASE_URI.buildUpon()
                .appendPath(CAT_PATH).build();
 
        public static class Cols {
            public static final String cat_id = BaseColumns._ID;
            public static final String key_2_catname="name";
            public static final String key_3_catstatus="status";
 
        }
    }
}