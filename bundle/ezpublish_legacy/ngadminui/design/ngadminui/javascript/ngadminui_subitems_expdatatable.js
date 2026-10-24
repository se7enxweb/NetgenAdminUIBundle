/**
 * The Netgen Admin UI sub-items table on Exponential UI's $.fn.expDataTable (exp::datatable), without YUI.
 *
 * Started by children_detailed.tpl when the legacy kernel provides Exponential UI instead of YUI
 * (window.Exp && Exp.$.fn.expDataTable), with the same four objects the YUI version
 * (ezajaxsubitems_datatable.js, used on kernels that still ship YUI) is given:
 *
 *   ngAdminUiSubitemsExpDataTable.init(confObj, labelsObj, createGroups, createOptions)
 *
 * It keeps what the YUI table did: the ezjscnode::subtree request (GET, same arguments), the cache of 20 pages,
 * sorting, the pagers in #bpg and #tpg, rows per page saved as admin_list_limit, the shown columns in the
 * eZSubitemColumns cookie (one sub-value per navigation part), inline priority editing through
 * ezjscnode::updatepriority, the Select, Create new subitem, More actions and Table options controls (same ids,
 * same containers, same form fields posted) and the context menu of each row, opened from the class icon.
 */
var ngAdminUiSubitemsExpDataTable = (function () {
    'use strict';

    // ---- the eZSubitemColumns cookie, as YAHOO.util.Cookie.getSub / setSub wrote it ----------------------------
    // name=sub1=value1&sub2=value2, each sub name and value encodeURIComponent()ed; the value is escape()d first

    function readSubs(name) {
        var all = document.cookie ? document.cookie.split(/;\s/g) : [], subs = {};
        for (var i = 0; i < all.length; i++) {
            var eq = all[i].indexOf('=');
            if (eq === -1 || decodeURIComponent(all[i].substring(0, eq)) !== name) { continue; }
            var hash = all[i].substring(eq + 1);
            if (!hash) { break; }
            hash.split('&').forEach(function (pair) {
                var k = pair.indexOf('=');
                if (k === -1) { return; }
                try { subs[decodeURIComponent(pair.substring(0, k))] = decodeURIComponent(pair.substring(k + 1)); } catch (e) { /* not ours */ }
            });
            break;
        }
        return subs;
    }

    function getCookieSubMultiValue(name, sub) {
        var subs = readSubs(name);
        if (!Object.prototype.hasOwnProperty.call(subs, sub)) { return null; }
        return window.unescape(subs[sub]).split('|');
    }

    function setCookieSubMultiValue(name, sub, values, secure) {
        var subs = readSubs(name), expires = new Date(), parts = [];
        subs[sub] = window.escape(values.join('|'));
        expires.setFullYear(expires.getFullYear() + 10);
        Object.keys(subs).forEach(function (k) { parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(subs[k])); });
        document.cookie = encodeURIComponent(name) + '=' + parts.join('&') + '; expires=' + expires.toUTCString() +
                          '; path=/' + (secure ? '; secure' : '');
    }

    function init(confObj, labelsObj, createGroups, createOptions) {
        var $ = window.Exp.$;
        var shownColumns = getCookieSubMultiValue(confObj.cookieName, confObj.navigationPart);
        if (shownColumns === null) { shownColumns = confObj.defaultShownColumns[confObj.navigationPart]; }
        var L = labelsObj.DATA_TABLE_COLS, A = labelsObj.ACTION_BUTTONS, O = labelsObj.TABLE_OPTIONS;
        var form = function () { return $('form[name=children]').first(); };
        var selectedCount = function () { return $('form[name=children] input.ezsubitems_delete_checkbox:checked').length; };

        // ---- cell formatters (the YUI version's, same HTML) ----------------------------------------------------
        var formatName = function (row) {
            return '<a href="' + row.url + '" title="' + row.name + '">' + row.name + '</a>';
        };
        // the class icon opens the row's context menu
        var customMenu = function (row) {
            var createhereMenu = (confObj.classesString != '') ? -1 : "'child-menu-create-here'";
            var translationArray = [];
            $.each(row.translations || [], function (i, e) { translationArray.push({ 'locale': e, 'name': confObj.languages[e] }); });
            var a = $('<a></a>').attr({ href: '#', role: 'button', 'aria-label': row.name, 'aria-haspopup': 'menu' })
                .append($('<div></div>').html(row.class_icon || ''));
            a.on('click', function (e) {
                e.preventDefault();
                var ev = e.originalEvent || e;
                if (!ev.pageX && !ev.pageY) {   // opened with the keyboard: under the link
                    var r = this.getBoundingClientRect();
                    ev = { pageX: r.left + window.pageXOffset, pageY: r.bottom + window.pageYOffset };
                }
                window.ezpopmenu_showTopLevel(ev, 'SubitemsContextMenu', {
                    '%nodeID%': row.node_id, '%objectID%': row.contentobject_id, '%version%': row.version,
                    '%languages%': translationArray, '%classList%': confObj.classesString
                }, row.name, row.node_id, createhereMenu);
            });
            return a;
        };
        var thumbView = function (row) {
            var url = encodeURI(row.thumbnail_url || '');
            if (url) {
                var thBack = 'background: url(\'' + url.replace(/'/g, "\\'") + '\') no-repeat;';
                var thWidth = ' width: ' + row.thumbnail_width + 'px;';
                var thHeight = ' height: ' + row.thumbnail_height + 'px;';
                return '<div class="thumbview"><div id="thumbfield" class="thumbfield"></div><span><div style="' + thBack + thWidth + thHeight + '"></div></span></div>';
            }
            return '';
        };
        var translationView = function (row) {
            var html = '';
            $.each(row.translations || [], function (i, e) {
                if (row.can_edit === true) { html += '<a href="' + confObj.editPrefixURL + '/' + row.contentobject_id + '/f/' + e + '">'; }
                html += '<img src="' + confObj.flagIcons[e] + '" width="18" height="12" style="margin-right: 4px;" alt="' + e + '" title="' + e + '"/>';
                if (row.can_edit === true) { html += '</a>'; }
            });
            return html;
        };
        var text = function (key) {
            return function (row) { var v = row[key]; return v === null || v === undefined ? '' : String(v).replace(/&/g, '&#38;').replace(/</g, '&#60;').replace(/>/g, '&#62;'); };
        };

        var columns = [
            { key: 'checkbox', label: '' },
            { key: 'crank', label: '', render: customMenu },
            { key: 'thumbnail', label: L.thumbnail, labelHidden: true, render: thumbView },
            { key: 'name', label: L.name, sortable: true, render: formatName },
            { key: 'hidden_status_string', label: L.visibility, sortable: true, render: text('hidden_status_string') },
            { key: 'class_name', label: L.type, sortable: true, render: text('class_name') },
            { key: 'creator', label: L.modifier, render: text('creator') },
            { key: 'modified_date', label: L.modified, sortable: true, render: text('modified_date') },
            { key: 'published_date', label: L.published, sortable: true, render: text('published_date') },
            { key: 'translations', label: L.translations, render: translationView },
            { key: 'section', label: L.section, sortable: true, render: text('section') },
            { key: 'node_id', label: L.nodeid, sortable: true, render: text('node_id') },
            { key: 'node_remote_id', label: L.noderemoteid, render: text('node_remote_id') },
            { key: 'contentobject_id', label: L.objectid, sortable: true, render: text('contentobject_id') },
            { key: 'contentobject_remote_id', label: L.objectremoteid, render: text('contentobject_remote_id') },
            { key: 'contentobject_state', label: L.objectstate, render: text('contentobject_state') },
            { key: 'priority', label: L.priority, sortable: true, editable: 'number', render: text('priority') }
        ];
        // Hidden columns from the cookie, with the ini setting as fallback; neither: all columns are shown
        if (shownColumns && shownColumns.length !== 0) {
            columns.forEach(function (c) { if (shownColumns.indexOf(c.key) === -1 && c.label !== '') { c.hidden = true; } });
        }

        // the server's rows, as the YUI DataSource's responseSchema parsed them
        var parseRow = function (r) {
            var row = $.extend({}, r);
            row.creator = r.creator && r.creator.name ? r.creator.name : '?';
            row.section = r.section && r.section.name ? r.section.name : '?';
            row.translations = r.translations ? r.translations.language_list : undefined;
            return row;
        };

        // The YUI version put Create new subitem and Table options into containers of their own
        var placeButtons = function () {
            $('#action-controls-new').append($('#ezbtn-new'));
            $('#action-controls-options').append($('#ezbtn-options'));
        };

        var $list = $('#content-sub-items-list');
        $list.expDataTable({
            columns: columns,
            rowKey: 'node_id',
            source: {
                // GET <ezjscore/call/ezjscnode::subtree::node>::limit::offset::sort::order::filter?ContentType=json
                url: function (s) {
                    return confObj.dataSourceURL + '::' + s.limit + '::' + s.offset + '::' + s.sort.key + '::' +
                           (s.sort.dir === 'asc' ? '1' : '0') + '::' + confObj.nameFilter + '?ContentType=json';
                },
                parse: function (json) {
                    var c = (json && json.content) || {};
                    return { rows: (c.list || []).map(parseRow), total: Number(c.total_count) || 0 };
                },
                cache: 20
            },
            sort: { key: confObj.sortKey, dir: confObj.sortOrder === 1 ? 'asc' : 'desc' },
            paging: {
                limit: confObj.rowsPrPage,
                containers: ['#bpg'],
                compact: ['#tpg'],
                labels: { first: "<span data-icon='&#xe065;'></span>", last: "<span data-icon='&#xe068;'></span>",
                          prev: "<span data-icon='&#xe01e;'></span>", next: "<span data-icon='&#xe01c;'></span>" }
            },
            select: { key: 'checkbox', name: 'DeleteIDArray[]', className: 'ezsubitems_delete_checkbox',
                      value: function (row) { return row.node_id; }, label: function (row) { return row.name; },
                      header: false, ranges: false },
            columnToggle: {
                shown: shownColumns,
                save: function (keys) {
                    setCookieSubMultiValue(confObj.cookieName, confObj.navigationPart, keys, confObj.cookieSecure);
                    shownColumns = keys;
                }
            },
            inlineEdit: {
                canEdit: function (row) { return row.can_edit === true; },
                fn: 'ezjscnode::updatepriority',
                data: function (row, key, value) {
                    return { ContentNodeID: row.parent_node_id, ContentObjectID: row.contentobject_id,
                             PriorityID: [row.node_id], Priority: [value] };
                }
            },
            loading: labelsObj.DATA_TABLE.msg_loading,
            actionsContainer: '#action-controls',
            actions: [
                { id: 'ezbtn-items', label: A.select, menu: [
                    { id: 'ezopt-menu-check', label: A.select_sav, onSelect: function () { $list.find('input[type=checkbox]').prop('checked', true); this.syncAll(); this.emitSelect(); } },
                    { id: 'ezopt-menu-uncheck', label: A.select_sn, onSelect: function () { $list.find('input[type=checkbox]').prop('checked', false); this.syncAll(); this.emitSelect(); } },
                    { id: 'ezopt-menu-toggle', label: A.select_inv, onSelect: function () { $list.find('input[type=checkbox]').each(function () { this.checked = !this.checked; }); this.syncAll(); this.emitSelect(); } }
                ] },
                { id: 'ezbtn-new', label: A.create_new, disabled: createGroups.length === 0,
                  menu: createGroups.map(function (g, i) {
                      return { group: g, items: (createOptions[i] || []).map(function (o) { return { label: o.text, value: o.value, html: true }; }) };
                  }),
                  onSelect: function (item) {
                      form().append($('<input type="hidden" name="ClassID" />').val(item.value)).append($('<input type="hidden" name="NewButton" />')).trigger('submit');
                  } },
                { id: 'ezbtn-more', label: A.more_actions,
                  menu: function () {
                      if (selectedCount() === 0) { return [{ label: A.more_actions_no, disabled: true }]; }
                      return [
                          { id: 'ezopt-menu-remove', label: A.more_actions_rs, value: 0 },
                          { id: 'ezopt-menu-move', label: A.more_actions_ms, value: 1 }
                      ];
                  },
                  onSelect: function (item) {
                      if (selectedCount() === 0) { return; }
                      if (item.value === 0) {
                          form().append($('<input type="hidden" name="RemoveButton" />')).trigger('submit');
                      } else {
                          form().append($('<input type="hidden" name="MoveButton" />')).trigger('submit');
                      }
                  } }
            ],
            tableOptions: {
                button: { id: 'ezbtn-options', label: A.table_options },
                container: '#to-dialog-container',
                title: O.header,
                close: O.button_close,
                limits: {
                    legend: O.header_noipp,
                    items: [{ id: 1, count: 10 }, { id: 2, count: 25 }, { id: 3, count: 50 }],
                    onSelect: function (item) {
                        window.Exp.prefs.set('admin_list_limit', item.id).catch(function (e) {
                            if (window.console) { window.console.warn('sub items: admin_list_limit was not saved', e && e.message); }
                        });
                    }
                },
                columns: { legend: O.header_vtc }
            },
            onRender: placeButtons
        });
        placeButtons();
        return $list.data('expDataTable');
    }

    return { init: init, getCookieSubMultiValue: getCookieSubMultiValue, setCookieSubMultiValue: setCookieSubMultiValue };
}());
