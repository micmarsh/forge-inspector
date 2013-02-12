var Database;

Database = (function() {
  var Entities;

  Database.name = 'Database';

  Database.prototype.TEXT_COL = "text";

  Database.prototype.LOC_COL = "localID";

  Database.prototype.SERV_COL = "id";

  Database.prototype.TIME_COL = "timestamp";

  Database.prototype.STATUS_COL = "status";

  function Database() {
    this.notes.TABLE_NAMES = this.TABLE_NAMES;
    this.notes._whereClause = this._whereClause;
    this.notes.text = this.TEXT_COL;
    this.notes.id = this.SERV_COL;
    this.notes.localID = this.LOC_COL;
    this.notes.status = this.STATUS_COL;
    this.notes.timestamp = this.TIME_COL;
  }

  Database.prototype.TABLE_NAMES = {
    notes: "Notes",
    hashtags: "NoteTag",
    attags: "NoteContact",
    emails: "NoteEmail",
    urls: "NoteURL"
  };

  Database.prototype.CREATE_TABLES = (function() {
    var COLUMN, CREATE, ENTITY_COLS, LOC_ID, SCHEMA, TABLE_NAMES, i, schema, that;
    that = Database.prototype;
    CREATE = "CREATE TABLE ";
    TABLE_NAMES = _.values(that.TABLE_NAMES);
    ENTITY_COLS = ["hashtags", "attags", "emails", "urls"];
    LOC_ID = "" + that.LOC_COL + " INTEGER PRIMARY KEY ";
    SCHEMA = [("(" + that.TEXT_COL + " TEXT, " + LOC_ID + ", " + that.SERV_COL + " TEXT UNIQUE,") + (" " + that.TIME_COL + " TEXT, " + that.STATUS_COL + " TEXT)")].concat((function() {
      var _i, _len, _results;
      _results = [];
      for (_i = 0, _len = ENTITY_COLS.length; _i < _len; _i++) {
        COLUMN = ENTITY_COLS[_i];
        _results.push("(" + that.LOC_COL + " INTEGER, " + COLUMN + " TEXT)");
      }
      return _results;
    })());
    return (function() {
      var _i, _len, _results;
      _results = [];
      for (i = _i = 0, _len = SCHEMA.length; _i < _len; i = ++_i) {
        schema = SCHEMA[i];
        _results.push({
          name: TABLE_NAMES[i],
          schema: schema
        });
      }
      return _results;
    })();
  })();

  Database.prototype.lastSync = function(time) {
    if (time != null) {
      return bc.core.cache(this.last, time);
    } else {
      return bc.core.cache(this.last);
    }
  };

  Database.prototype._whereClause = function(args) {
    var attags, clauses, dirty, hashtags, search;
    hashtags = args.hashtags, attags = args.attags, search = args.search, dirty = args.dirty;
    clauses = _.compact([(hashtags.length || attags.length ? " " + Database.prototype.LOC_COL + " in (" + (Database.prototype._buildFilterQuery(hashtags, attags)) + ")" : ''), (search ? " " + Database.prototype.TEXT_COL + " like '%" + search + "%' collate nocase " : ''), (dirty === true ? " " + Database.prototype.STATUS_COL + " != 'synced' " : ''), (dirty === false ? " " + Database.prototype.STATUS_COL + " != 'delete' " : '')]);
    if (clauses.length) {
      return "where " + clauses.join(' and ');
    } else {
      return '';
    }
  };

  Database.prototype.clear = function(options) {
    var error, success;
    success = options.success, error = options.error;
    return forge.internal.call('database.dropTables', {
      tables: _.values(this.TABLE_NAMES)
    }, success, error);
  };

  Database.prototype._buildFilterQuery = function(hashtags, attags) {
    var item, name, queries, tags, _i, _len, _ref;
    tags = {
      hashtags: this._prependCharacter(hashtags, '#'),
      attags: this._prependCharacter(attags, '@')
    };
    queries = {};
    _ref = Object.keys(tags);
    for (_i = 0, _len = _ref.length; _i < _len; _i++) {
      name = _ref[_i];
      queries[name] = (function() {
        var _j, _len1, _ref1, _results;
        _ref1 = tags[name];
        _results = [];
        for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
          item = _ref1[_j];
          _results.push("select distinct " + Database.prototype.LOC_COL + " from " + this.TABLE_NAMES[name] + " where " + name + " == '" + item + "'");
        }
        return _results;
      }).call(this);
    }
    return _.compact([queries.hashtags.join(' intersect '), queries.attags.join(' intersect ')]).join(' intersect ');
  };

  Database.prototype._prependCharacter = function(array, character) {
    return array.map(function(str) {
      if (str.startsWith(character)) {
        return str;
      } else {
        return character + str;
      }
    });
  };

  Database.prototype._getStuff = function(args) {
    var error, newSuccess, query, success, type;
    query = args.query, type = args.type, success = args.success, error = args.error;
    newSuccess = function(dbData) {
      return success(dbData, args);
    };
    console.log(query);
    return forge.internal.call('database.query', {
      query: query
    }, newSuccess, error);
  };

  Entities = (function() {

    Entities.name = 'Entities';

    Entities.prototype.TABLE_NAMES = Database.prototype.TABLE_NAMES;

    function Entities(type) {
      this._type = type;
    }

    Entities.prototype._buildQuery = function(args) {
      return ("select distinct " + args.type + " as name, count(" + args.type + ") as count") + (" from " + this.TABLE_NAMES[args.type] + " ") + Database.prototype._whereClause(args) + (" group by " + args.type + ";");
    };

    Entities.prototype.get = function(args) {
      var attags, error, hashtags, success, type;
      args || (args = {});
      attags = args.attags, hashtags = args.hashtags, type = args.type, success = args.success, error = args.error;
      args = {
        attags: attags,
        hashtags: hashtags,
        type: type,
        success: success,
        error: error
      };
      args.hashtags || (args.hashtags = []);
      args.attags || (args.attags = []);
      args.type = this._type;
      args.query = {
        query: this._buildQuery(args),
        args: []
      };
      return Database.prototype._getStuff(args);
    };

    return Entities;

  })();

  /*
          General form of every function "db.<collection>.<function>(model, options)"
          (model, options) could just be (options)

          db.callAsync [
              {
                  method: "collection.function"
                  model: model
                  options:
                      dirty: maybe
                      search: "blah"
                      .
                      .
                      success: -> "woot"
                      error: -> "shit"
              }
          ]
  */


  Database.prototype.callAsync = function(calls, context) {
    var collection, currentCall, error, func, method, model, options, success, _ref;
    if (calls.length) {
      currentCall = calls[0];
      method = currentCall.method, model = currentCall.model, options = currentCall.options;
      options || (options = {});
      success = options.success, error = options.error;
      _ref = method.split('.'), collection = _ref[0], func = _ref[1];
      options.success = function(arg) {
        if (success) success(arg);
        console.log("Success calling " + method + ", calling next method!");
        return context.callAsync(calls.slice(1), context);
      };
      options.error = function(arg) {
        if (error) error(arg);
        console.error(arg);
        console.error("Error calling " + method + ", calling next method anyway");
        return context.callAsync(calls.slice(1), context);
      };
      return this[collection][func]((func === 'get' ? options : model), options);
    }
  };

  Database.prototype.hashtags = new Entities('hashtags');

  Database.prototype.attags = new Entities('attags');

  Database.prototype.notes = {
    create: function(model, options) {
      var error, success,
        _this = this;
      options || (options = {});
      success = options.success, error = options.error;
      options.success = function(ids) {
        var i, _i, _ref;
        if (_.isArray(model)) {
          for (i = _i = 0, _ref = model.length; 0 <= _ref ? _i < _ref : _i > _ref; i = 0 <= _ref ? ++_i : --_i) {
            model[i].set(_this.localID, ids[i]);
          }
        } else {
          model.set(_this.localID, ids[0]);
        }
        return _this._writeAll(_this._buildAddEntitiesQueries(_this._arrayCheck(model)), {
          success: success,
          error: error
        });
      };
      return this._makeAndCallQuery(model, options, $.proxy(this._buildAddNoteQuery, this), 'create');
    },
    update: function(model, options) {
      var error, success,
        _this = this;
      options || (options = {});
      success = options.success, error = options.error;
      options.success = function() {
        var bigArray;
        bigArray = [_this._buildRemoveEntitiesQueries(_this._arrayCheck(model)), _this._buildAddEntitiesQueries(_this._arrayCheck(model))];
        return _this._writeAll(_.flatten(bigArray), {
          success: success,
          error: error
        });
      };
      return this._makeAndCallQuery(model, options, $.proxy(this._buildUpdateNoteQuery, this), 'update');
    },
    'delete': function(model, options) {
      var dirty, error, success,
        _this = this;
      options || (options = {});
      success = options.success, error = options.error, dirty = options.dirty;
      options.success = function() {
        return _this._writeAll(_this._buildRemoveEntitiesQueries(_this._arrayCheck(model)), {
          success: success,
          error: error
        });
      };
      if (Boolean(dirty)) {
        return this._makeAndCallQuery(model, options, $.proxy(this._buildUpdateNoteQuery, this), 'delete');
      } else {
        return this._makeAndCallQuery(model, options, $.proxy(this._buildDeleteNoteQuery, this), 'delete');
      }
    },
    clean: function(model, options) {
      options || (options = {});
      options.dirty = false;
      if (!_.isArray(model)) {
        if (model.get(this.status) === 'delete') {
          return this["delete"](model, options);
        } else {
          options.cleaning = true;
          return this.update(model, options);
        }
      } else {
        if (options.error) options.error();
        throw new Error("clean takes only a single object");
      }
    },
    sync: function(models, options) {
      console.log('fake sync function!');
      if (options.success) return options.success();
    },
    get: function(args) {
      args || (args = {});
      args.query = this._buildFetchQuery(args);
      args.type = "notes";
      return Database.prototype._getStuff(args);
    },
    _makeAndCallQuery: function(model, options, queryFunction, ifDirty) {
      var addQuery, cleaning, dirty, note, queries, _i, _len;
      options || (options = {});
      cleaning = options.cleaning, dirty = options.dirty;
      queries = [];
      addQuery = function(note) {
        note.set(this.status, dirty ? ifDirty : 'synced');
        return queries.push({
          query: queryFunction(note, cleaning),
          args: !dirty && ifDirty === 'delete' ? [] : [note.get('text')]
        });
      };
      if (_.isArray(model)) {
        console.log('about to make some queries');
        for (_i = 0, _len = model.length; _i < _len; _i++) {
          note = model[_i];
          addQuery(note);
        }
      } else {
        addQuery(model);
      }
      return this._writeAll(queries, options);
    },
    _writeAll: function(queries, options) {
      var error, q, success, _i, _len;
      options || (options = {});
      success = options.success, error = options.error;
      if (false) {
        console.log('##############################################\nwoot we debuggin\'');
        console.log(queries);
        for (_i = 0, _len = queries.length; _i < _len; _i++) {
          q = queries[_i];
          console.log(q.text);
          console.log(q.query);
        }
        if (success) success([1, 2, 3, 4, 4]);
        console.log('#################################################################333\n\n\n');
      }
      return forge.internal.call('database.writeAll', {
        queries: queries
      }, function(ids) {
        if (success) return success(ids);
      }, function(err) {
        if (error) return error();
      });
    },
    _arrayCheck: function(model) {
      if (_.isArray(model)) {
        return model;
      } else {
        return [model];
      }
    },
    _buildAddEntitiesQueries: function(models) {
      var note;
      return _.flatten((function() {
        var _i, _len, _results;
        _results = [];
        for (_i = 0, _len = models.length; _i < _len; _i++) {
          note = models[_i];
          _results.push(this._buildNoteEntityQueries(Fetch.findEntities(note.get(this.text)), note.get(this.localID)));
        }
        return _results;
      }).call(this));
    },
    _buildNoteEntityQueries: function(entities, id) {
      var entName, entity, results, _i, _j, _len, _len1, _ref, _ref1;
      results = [];
      _ref = Object.keys(entities);
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        entName = _ref[_i];
        _ref1 = entities[entName];
        for (_j = 0, _len1 = _ref1.length; _j < _len1; _j++) {
          entity = _ref1[_j];
          results.push({
            query: ("insert into " + this.TABLE_NAMES[entName] + " ") + ("(" + this.localID + " , " + entName + ") values (" + id + ",\"" + (entity.toLowerCase()) + "\")"),
            args: []
          });
        }
      }
      return results;
    },
    _buildRemoveEntitiesQueries: function(models) {
      var note, results, _i, _len;
      results = [];
      for (_i = 0, _len = models.length; _i < _len; _i++) {
        note = models[_i];
        results.push(this._buildRemoveNoteEntityQueries(note.get(this.localID)));
      }
      return _.flatten(results);
    },
    _buildRemoveNoteEntityQueries: function(id) {
      var makeObject, tableName, _i, _len, _ref, _results;
      makeObject = function(query) {
        return {
          query: query,
          args: []
        };
      };
      _ref = _.values(this.TABLE_NAMES).slice(1);
      _results = [];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        tableName = _ref[_i];
        _results.push(makeObject("delete from " + tableName + " where " + this.localID + "=" + id));
      }
      return _results;
    },
    _buildSetNoteQuery: function(model) {
      return "insert or replace into Notes" + ("(" + this.text + "," + this.id + "," + this.timestamp + "," + this.status + ") ") + (" values (?,\"" + (model.get(this.id)) + "\",") + ("\"" + (model.get(this.timestamp)) + "\",") + (" \"" + (model.get(this.status)) + "\")");
    },
    _buildAddNoteQuery: function(model) {
      return ("insert into Notes (" + this.text + "," + this.id + ",") + ("" + this.timestamp + "," + this.status + ") ") + (" values (?,\"" + (model.get(this.id)) + "\",") + ("\"" + (model.get(this.timestamp)) + "\",") + (" \"" + (model.get(this.status)) + "\")");
    },
    _checkNewness: function(model) {
      if (model.isNew()) {
        return " " + this.localID + "=\"" + (model.get(this.localID)) + "\"";
      } else {
        return " " + this.id + "=\"" + (model.get(this.id)) + "\"";
      }
    },
    _buildUpdateNoteQuery: function(model, cleaning) {
      return ("update Notes set " + this.text + "=?, " + this.id + "=\"" + (model.get(this.id)) + "\",") + ("" + this.timestamp + "=\"" + (model.get(this.timestamp)) + "\",") + ("" + this.status + "=\"" + (model.get(this.status)) + "\" where ") + (cleaning ? " " + this.localID + "=\"" + (model.get(this.localID)) + "\"" : this._checkNewness(model));
    },
    _buildDeleteNoteQuery: function(model) {
      return "delete from Notes where " + this._checkNewness(model);
    },
    _buildFetchQuery: function(args) {
      var limit, skip;
      args.hashtags || (args.hashtags = []);
      args.attags || (args.attags = []);
      args.skip || (args.skip = 0);
      args.limit || (args.limit = 25);
      args.dirty || (args.dirty = false);
      skip = args.skip, limit = args.limit;
      return "select * from Notes " + this._whereClause(args) + (" order by " + this.timestamp + " desc ") + (" limit " + skip + "," + (skip + limit) + ";");
    }
  };

  return Database;

})();
