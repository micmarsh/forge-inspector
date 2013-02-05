var Database;

Database = (function() {
  var Entities;

  Database.name = 'Database';

  function Database() {
    this.notes.TABLE_NAMES = this.TABLE_NAMES;
    this.notes._whereClause = this._whereClause;
  }

  Database.prototype.TABLE_NAMES = {
    hashtags: "NoteTag",
    attags: "NoteContacts",
    emails: "NoteEmail",
    urls: "NoteURL"
  };

  Database.prototype._whereClause = function(args) {
    var attags, clauses, dirty, hashtags, search;
    hashtags = args.hashtags, attags = args.attags, search = args.search, dirty = args.dirty;
    clauses = _.compact([(hashtags.length || attags.length ? " localID in (" + (Database.prototype._buildFilterQuery(hashtags, attags)) + ")" : ''), (search ? " text like '%" + search + "%' collate nocase " : ''), (dirty ? " sync_status != 'synced' " : '')]);
    if (clauses.length) {
      return "where " + clauses.join(' and ');
    } else {
      return '';
    }
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
          _results.push("select distinct localID from " + this.TABLE_NAMES[name] + " where " + name + " == '" + item + "'");
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

  Entities = (function() {

    Entities.name = 'Entities';

    Entities.prototype.TABLE_NAMES = Database.prototype.TABLE_NAMES;

    function Entities(type) {
      this._type = type;
    }

    Entities.prototype._buildQuery = function(args) {
      return ("select distinct " + args.type + " as name, count(" + args.type + ") as count") + (" from " + this.TABLE_NAMES[args.type] + " ") + Database.prototype._whereClause(args) + (" order by " + args.type + " desc");
    };

    Entities.prototype.get = function(args) {
      var attags, hashtags, type;
      attags = args.attags, hashtags = args.hashtags, type = args.type;
      args = {
        attags: attags,
        hashtags: hashtags,
        type: type
      };
      args.hashtags || (args.hashtags = []);
      args.attags || (args.attags = []);
      args.type = this._type;
      return this._buildQuery(args);
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
      return this[collection][func](model, options);
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
            model[i].set('localID', ids[i]);
          }
        } else {
          model.set('localID', ids[0]);
        }
        return _this._writeAll(_this._buildAddEntitiesQueries(_this._arrayCheck(model)), {
          success: success,
          error: error
        });
      };
      return this._makeAndCallQuery(model, options, this._buildAddNoteQuery, 'create');
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
    clean: function(model) {
      if (model.get('sync') === 'delete') {
        return this["delete"](model);
      } else {
        return this.update(model, {
          cleaning: true
        });
      }
    },
    get: function(args) {
      args || (args = {});
      args.query = this._buildFetchQuery(args);
      args.type = "notes";
      return this._getStuff(args);
    },
    _getStuff: function(args) {
      var error, query, success, type;
      query = args.query, type = args.type, success = args.success, error = args.error;
      console.log(query);
      return forge.internal.call('database.query', {
        query: query
      }, success, error);
    },
    _makeAndCallQuery: function(model, options, queryFunction, ifDirty) {
      var cleaning, dirty, note, queries, wrapArray, _i, _len;
      options || (options = {});
      cleaning = options.cleaning;
      if (_.isArray(model)) {
        queries = [];
        console.log('about to make some queries');
        for (_i = 0, _len = model.length; _i < _len; _i++) {
          note = model[_i];
          note.set('sync', 'synced');
          queries.push({
            query: queryFunction(note, cleaning),
            args: [note.get('text')]
          });
        }
        console.log('about to run some queries');
        return this._writeAll(queries, options);
      } else {
        dirty = Boolean(options.dirty);
        if (dirty) {
          model.set('sync', ifDirty);
        } else {
          model.set('sync', 'synced');
        }
        wrapArray = [
          {
            query: queryFunction(model, cleaning),
            args: [model.get('text')]
          }
        ];
        console.log('about to call some queries');
        return this._writeAll(wrapArray, options);
      }
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
      var note, results, _i, _len;
      results = [];
      for (_i = 0, _len = models.length; _i < _len; _i++) {
        note = models[_i];
        results.push(this._buildNoteEntityQueries(Fetch.findEntities(note.get('text')), note.get('localID')));
      }
      return _.flatten(results);
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
            query: ("insert into " + this.TABLE_NAMES[entName] + " ") + ("(localID , " + entName + ") values (" + id + ",\"" + (entity.toLowerCase()) + "\")"),
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
        results.push(this._buildRemoveNoteEntityQueries(note.get('localID')));
      }
      return _.flatten(results);
    },
    _buildRemoveNoteEntityQueries: function(id) {
      var makeObject, tableName, _i, _len, _ref, _results;
      makeObject = function(query) {
        return {
          query: query,
          args: ['poop']
        };
      };
      _ref = _.values(this.TABLE_NAMES);
      _results = [];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        tableName = _ref[_i];
        _results.push(makeObject("delete from " + tableName + " where localID=" + id));
      }
      return _results;
    },
    _buildAddNoteQuery: function(model) {
      return "insert into Notes (text,id,timestamp,sync) " + (" values (?,\"" + (model.get('id')) + "\",") + ("\"" + (model.get('timestamp')) + "\",") + (" \"" + (model.get('sync')) + "\")");
    },
    _checkNewness: function(model) {
      if (model.isNew()) {
        return " localID=\"" + (model.get('localID')) + "\"";
      } else {
        return " id=\"" + model.id + "\"";
      }
    },
    _buildUpdateNoteQuery: function(model, cleaning) {
      return ("update Notes set text=?, id=\"" + (model.get('id')) + "\",") + ("timestamp=\"" + (model.get('timestamp')) + "\",") + ("sync=\"" + (model.get('sync')) + "\" where ") + (cleaning ? " localID=\"" + (model.get('localID')) + "\"" : this._checkNewness(model));
    },
    _buildDeleteNoteQuery: function(model) {
      console.log("apparently " + this._checkNewness + " doesn't exist");
      return "delete from Notes where " + this._checkNewness(model);
    },
    _buildFetchQuery: function(args) {
      var limit, skip;
      args.hashtags || (args.hashtags = []);
      args.attags || (args.attags = []);
      args.skip || (args.skip = 0);
      args.limit || (args.limit = 25);
      skip = args.skip, limit = args.limit;
      return "select * from Notes " + this._whereClause(args) + " order by timestamp desc " + (" limit " + skip + "," + (skip + limit) + ";");
    }
  };

  return Database;

})();

