// Bricata's Web based CMC UI.
//
// Copyright (c) 2014 - Bricata, LLC
//

var selected_events = [];
var flash_message = [];
var csrf = $('meta[name="csrf-token"]').attr('content');


function set_cookie () {
	var expires,
		date = new Date();

	date.setTime(date.getTime()+(24*60*60*1000));
	expires = "; expires="+date.toGMTString();
	document.cookie = "csrf=" + csrf + expires + "; path=/";
}

set_cookie();

$.fn.buttonLoading = function () {
	var width = $(this).outerWidth(true) - 2;
	var height = $(this).outerHeight(false) - 2;

	$(this).addClass('loading').css({
		width: width,
		height: height
	});
};

$.deparam = jq_deparam = function (params, coerce) {
	var obj = {};
	var coerce_types = {'true': !0, 'false': !1, 'null': null};

	$.each(params.replace(/\+/g, ' ').split('&'), function (j, v) {
		var param = v.split('='),
			key = decodeURIComponent(param[0]),
			val,
			cur = obj,
			i = 0,

			keys = key.split(']['),
			keys_last = keys.length - 1;

		if (/\[/.test(keys[0]) && /\]$/.test(keys[keys_last])) {
			keys[keys_last] = keys[keys_last].replace(/\]$/, '');

			keys = keys.shift().split('[').concat(keys);

			keys_last = keys.length - 1;
		} else {
			keys_last = 0;
		}

		if (param.length === 2) {
			val = decodeURIComponent(param[1]);

			if (coerce) {
				val = val && !isNaN(val) ? +val              // number
					: val === 'undefined' ? undefined         // undefined
					: coerce_types[val] !== undefined ? coerce_types[val] // true, false, null
					: val;                                                // string
			}

			if (keys_last) {
				for (; i <= keys_last; i++) {
					key = keys[i] === '' ? cur.length : keys[i];
					cur = cur[key] = i < keys_last
						? cur[key] || ( keys[i + 1] && isNaN(keys[i + 1]) ? {} : [] )
						: val;
				}

			} else {

				if ($.isArray(obj[key])) {
					obj[key].push(val);

				} else if (obj[key] !== undefined) {
					obj[key] = [obj[key], val];

				} else {
					obj[key] = val;
				}
			}

		} else if (key) {
			obj[key] = coerce
				? undefined
				: '';
		}
	});

	return obj;
};

function post_to_url(path, params, method) {
	method = method || "post";

	var form = document.createElement("form");
	form.setAttribute("method", method);
	form.setAttribute("action", path);

	for (var key in params) {
		if (params.hasOwnProperty(key)) {
			var hiddenField = document.createElement("input");
			hiddenField.setAttribute("type", "hidden");
			hiddenField.setAttribute("name", key);

			var value = params[key];
			if (typeof value === "object") {
				hiddenField.setAttribute("value", JSON.stringify(value));
			} else if (typeof value === "string") {
				hiddenField.setAttribute("value", value);
			} else if (typeof value === "boolean") {
				hiddenField.setAttribute("value", value);
			}

			form.appendChild(hiddenField);
		}
	}

	document.body.appendChild(form);
	form.submit();
}

var SearchRule;
SearchRule = function () {

	function SearchRule(selectedData, callback) {
		var self = this,
			selectData = JSON.parse(selectedData);
		self.html = Handlebars.templates['search-rule']({});
		self.columns = selectData.columns;
		self.operators = selectData.operators;
		self.selectData = selectData;
		self.classifications = selectData.classifications;
		self.sensors = selectData.sensors;
		self.users = selectData.users;
		self.signatures = selectData.signatures;
		self.severities = selectData.severities;
		self.protocol = selectData.protocol;
		self.has_note = selectData.has_note;


		self.init()

		return self;
	}

	SearchRule.prototype = {

		init: function (callback) {
			var self = this;
			var width = "368px";

			self.sensors_html = Handlebars.templates['select']({
				name: "sensors-select",
				width: width,
				multiple: false,
				data: self.sensors
			});

			self.classifications_html = Handlebars.templates['select']({
				name: "classifications-select",
				width: width,
				data: self.classifications
			});

			self.severity_html = Handlebars.templates['select']({
				name: "severities-select",
				width: width,
				data: self.severities
			});

			self.has_note_html = Handlebars.templates['select']({
				name: "has-note-select",
				width: width,
				data: self.has_note
			});

			self.signatures_html = Handlebars.templates['select']({
				name: "signatures-select",
				width: width,
				data: self.signatures
			});

			self.users_html = Handlebars.templates['select']({
				name: "users-select",
				width: width,
				data: self.users
			});

			self.protocol_html = Handlebars.templates['select']({
				name: "protocol-select",
				width: width,
				data: self.protocol
			});

			self.columns_html = Handlebars.templates['select']({
				name: "column-select",
				placeholder: "Choose a query term...",
				data: {
					value: self.columns
				}
			});

			self.operators_html = function ($html, data) {
				var select = Handlebars.templates['select']({
					name: "operators-select",
					data: {
						value: data
					}
				});

				$html.find('div.operator-select').html(select);
			};

			self.datetime_picker = function (that) {
				that.datetimepicker({
					timeFormat: 'hh:mm:ss',
					dateFormat: 'yy-mm-dd',
					numberOfMonths: 1,
					showSecond: true,
					separator: ' '
				});
			};

		},


		searchUI: function (data, callback) {
			var self = this,
				rules,
				title = $("#title2");

			title.after(Handlebars.templates['search'](data));

			rules = $('.rules');

			rules.on('click', '.search-content-add', function (e) {
				e.preventDefault();
				self.add(this);
			});

			rules.on('click', '.search-content-remove', function (e) {
				e.preventDefault();
				self.remove(this);
			});

			rules.on('click', 'div.search-content-enable input', function () {
				if ($(this).is(':checked')) {
					$(this)
						.parents('.search-content-box')
						.find('.value *, .operator-select *, .column-select *')
						.attr('disabled', false).css('opacity', 1);
				} else {
					$(this)
						.parents('.search-content-box')
						.find('.value *, .operator-select *, .column-select *')
						.attr('disabled', true).css('opacity', 0.8);
				}

				$('.add_chosen').trigger("liszt:updated");
			});

			$('#search').on('click', 'button.submit-search', function (e) {
				e.preventDefault();
				self.submit();
			});


			$('.cancel-saved-search-record').on('click', function (e) {
				window.location.href = '/search';
			});

			$('#saveCurrentSearch').on('click', function (e) {
				e.preventDefault();
				var searchRules = self.pack();

				if (searchRules && !$.isEmptyObject(searchRules.items)) {
					window.location.href = '/saved/searches/new';
				} else {
					flash_message.push({type: 'error', message: "You cannot save empty search rules."});
					flash();
				}
			});

			title.on('click', 'a.reset-search-form', function (e) {
				e.preventDefault();

				$('.rules').empty();

				self.add();
				self.add();
				self.add();
			});

			if (callback && (typeof callback === "function")) {
				callback();
			}
		},

		add: function (that, newOptions, callback) {
			var self = this;
			var options = {};

			if (options && (typeof options === "object")) {
				options = newOptions;
			}

			var $html = $(self.html);
			$html.find('div.column-select').html(self.columns_html);

			if (that && (typeof that === "object")) {
				$(that).parents('.search-content-box').after($html);
			} else {
				$('.rules').append($html);
			}

			$html.find('.add_chosen')
				.chosen({allow_single_deselect: true})
				.change(function (event, data) {
					var value = $(this).val();
					var that = $(this).parents('.search-content-box');

					if (value === "signature") {
						that.find('.value').html(self.signatures_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "signature_name") {
						that.find('.value').html('<input class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.operators_html($html, self.operators.contains);
					} else if (value === "sensor") {
						that.find('.value').html(self.sensors_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "classification") {
						that.find('.value').html(self.classifications_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "has_note") {
						that.find('.value').html(self.has_note_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "user") {
						that.find('.value').html(self.users_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "severity") {
						that.find('.value').html(self.severity_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "protocol") {
						that.find('.value').html(self.protocol_html);
						self.operators_html($html, self.operators.text_input);
					} else if (value === "start_time") {
						that.find('.value').html('<input id="time-' + new Date().getTime() + '" class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.datetime_picker(that.find('.value input:first'));
						self.operators_html($html, self.operators.datetime);
					} else if (value === "end_time") {
						that.find('.value').html('<input id="time-' + new Date().getTime() + '" class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.datetime_picker(that.find('.value input:first'));
						self.operators_html($html, self.operators.datetime);
					} else if (value === "payload") {
						that.find('.value').html('<input class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.operators_html($html, self.operators.more_text_input);
					} else if (value === "") {
						that.find('.value').html('<input class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.operators_html($html, self.operators.text_input);
					} else {
						that.find('.value').html('<input class="search-content-value" placeholder="Enter search value" name="" type="text">');
						self.operators_html($html, self.operators.text_input);
					}

					that.find('.add_chosen').chosen({
						allow_single_deselect: true
					});

					if (callback && (typeof callback === "function")) {
						callback(that);
					}

					that.trigger('bricata:search:change');
				});

			$('.search-content-box:first')
				.find('.search-content-remove')
				.css('opacity', 1)
				.unbind('hover')
				.unbind('mouseover')
			;

			return $html;
		},

		remove: function (that) {
			var self = this,
				selector = $('.search-content-box');
			if (selector.length > 2) {
				$(that).parents('.search-content-box').remove();
			} else if (selector.length == 2) {
				$(that).parents('.search-content-box').remove();

				$('.search-content-box:first')
					.find('.search-content-remove')
					.css('opacity', 0.4)
					.attr('title', 'You must have at least one search rule.')
					.tipsy({
						gravity: 's'
					});
			}
		},

		pack: function () {
			var self = this;
			var matchAll = false;
			var i = 0;

			var expires,
				date = new Date();

			if ($('.global-match-setting').val() === "all") {
				matchAll = true;
			}

			var json = {
				match_all: matchAll,
				items: {}
			};

			$('.search-content-box').each(function (index, item) {
				var enabled = $(item).find('.search-content-enable input').is(':checked');
				var column = $(item).find('.column-select select').val();
				var operator = $(item).find('.operator-select select').val();
				var value = $(item).find('.value input, .value select').val();

				if (enabled && (column !== "") || (value !== "")) {
					json.items[i] = {
						column: column,
						operator: operator,
						value: value,
						enabled: enabled
					};
					i++;
				}
			});

			date.setTime(date.getTime()+(24*60*60*1000));
			expires = "; expires="+date.toGMTString();
			document.cookie = "tmpSavedSearch=" + JSON.stringify(json) + expires + "; path=/";

			return json;
		},

		submit: function (callback, otherOptions) {
			var self = this;
			var search = self.pack();

			if (typeof otherOptions !== "object") {
				otherOptions = {};
			}

			var update_url = function () {
				if (history && history.pushState) {
					history.pushState(null, document.title, baseuri + '/results');
				}
			};

			if (callback && (typeof callback === "function")) {
				callback(search, self);
			}

			if (search && !$.isEmptyObject(search.items)) {
				if (otherOptions.search_id) {
					post_to_url(baseuri + '/results', {
						match_all: search.match_all,
						search: search.items,
						title: otherOptions.title,
						search_id: "" + otherOptions.search_id + "",
						authenticity_token: csrf
					});
				} else {
					post_to_url(baseuri + '/results', {
						match_all: search.match_all,
						search: search.items,
						authenticity_token: csrf
					});
				}
			} else {
				flash_message.push({type: 'error', message: "You cannot submit all empty search rules."});
				flash();
			}
		},

		build: function (search) {
			var self = this, data = {}, rules = {};

			if (typeof search === "string") {
				data = JSON.parse(search);
			} else if (typeof search === "object") {
				data = search;
			}

			if (data.items) {
				rules = data.items;
			} else if (data.search) {
				rules = data.search;
			}

			if (data.match_all && data.match_all === "false") {
				$('select.global-match-setting option[value="any"]').attr('selected', 'selected');
			} else {
				$('select.global-match-setting option[value="all"]').attr('selected', 'selected');
			}

			for (var id in rules) {
				var item = rules[id];

				var rule = self.add(false, {});

				var column = rule.find('div.column-select select');

				rule.bind('bricata:search:change', function () {
					var operator = $(this).find('div.operator-select select');
					var value = $(this).find('div.value select, div.value input');

					operator.find("option[value='" + item.operator + "']").attr('selected', 'selected');
					operator.trigger("liszt:updated");
					value.attr('value', item.value);

					rule.unbind('bricata:search:change');
				});

				rule.attr('data-rule-id', id);

				column.find("option[value='" + item.column + "']").attr('selected', 'selected');
				column.trigger("liszt:updated").trigger('change');

				if (item.enabled === "false") {
					rule.find('div.search-content-enable input').prop('checked', false);
					rule.find('.value *, .operator-select *, .column-select *')
						.attr('disabled', true).css('opacity', 0.8);
				}
			}

			$('.rules .add_chosen').trigger("liszt:updated");
		}

	};

	return SearchRule;
}();

function HCloader(element) {
	var $holder = $('div#' + element);
	$holder.fadeTo('slow', 0.2);

	var $el = $('<div class="cover-loader" />');

	$el.css({
		top: $holder.offset().top,
		left: $holder.offset().left,
		height: $holder.height(),
		width: $holder.width(),
		'line-height': $holder.height() + 'px'
	}).html('Loading...');

	$el.appendTo('body');
}

function clippyCopiedCallback(a) {
	var b = $('span#main_' + a);
	b.length != 0 && (b.attr("title", "copied!").trigger('tipsy.reload'), setTimeout(function () {
			b.attr("title", "copy to clipboard")
		},
		500))
}

function Queue() {
	if (!(this instanceof arguments.callee)) {
		return new arguments.callee(arguments);
	}
	var self = this;

	self.up = function () {
		var selector = $('span.queue-count'),
			current_count = parseInt(selector.html());
		selector.html(current_count + 1);
	};

	self.down = function () {
		var selector = $('span.queue-count'),
			current_count = parseInt(selector.html());
		selector.html(current_count - 1);
	};

}

function flash(data) {
	$('div#flash_message').remove();

	$.each(flash_message, function (index, data) {
		var message = Bricata.templates.flash(data);
		$('body').prepend(message);
		$('div#flash_message').fadeIn('slow').delay(2000).fadeOut("slow");
		flash_message = [];
	});

	return false;
}

function clear_selected_events() {
	selected_events = [];
	$('#selected_events').val('');

	var selector = $('#sessions-event-count-selected');
	if (selector.length > 0) {
		selector.data('count', 0);
	}
	return false;
}

function set_classification(class_id) {
	var selected_events = $('#selected_events').val();
	var current_page = $('#events').attr('data-action');
	var current_page_number = $('#events').attr('data-page');

	var direction = $('#events').attr('data-direction');
	var sort = $('#events').attr('data-sort');

	var classify_events = function () {
		$.post(baseuri + '/events/classify', {
			events: selected_events,
			classification: class_id,
			authenticity_token: csrf
		}, function () {
			if (current_page == "index") {
				clear_selected_events();
				$.getScript(baseuri + '/events?direction=' + direction + '&sort=' + sort + '&page=' + current_page_number);
			} else if (current_page == "queue") {
				clear_selected_events();
				$.getScript(baseuri + '/events/queue?direction=' + direction + '&sort=' + sort + '&page=' + current_page_number);
			} else if (current_page == "history") {
				clear_selected_events();
				$.getScript(baseuri + '/events/history?direction=' + direction + '&sort=' + sort + '&page=' + current_page_number);
			} else if (current_page == "results") {
				clear_selected_events();

				if ($('#search-params').length > 0) {

					var search_data = JSON.parse($('div#search-params').text());

					var direction = $('#results').attr('data-direction');
					var sort = $('#results').attr('data-sort');

					if (search_data) {
						$.ajax({
							url: $('input#current_url').val(),
							global: false,
							dataType: 'script',
							data: {
								match_all: search_data.match_all,
								search: search_data.search,
								authenticity_token: csrf,
								direction: direction,
								sort: sort
							},
							cache: false,
							type: 'POST',
							success: function (data) {
								$('div.content').fadeTo(500, 1);
								Bricata.helpers.remove_click_events(false);
								Bricata.helpers.recheck_selected_events();

								if (history && history.pushState) {
									history.pushState(null, document.title, $('input#current_url').val());
								}
								$.scrollTo('#header', 500);
							}
						});
					}
				}

			} //else {
			  // clear_selected_events();
			  // $.getScript(baseuri + '/events');
			  //}
			flash_message.push({type: 'success', message: "Event(s) Classified Successfully"});
		});
	};

	if (selected_events.length > 0) {
		$('div.content').fadeTo(500, 0.4);
		Bricata.helpers.remove_click_events(true);

		if ($('#events').data('action') === "sessions") {

			var count = 0;
			if ($('div#sessions-event-count-selected').length > 0) {
				count = $('div#sessions-event-count-selected').data('count');
			}

			$.post(baseuri + '/events/classify_sessions', {
				events: selected_events,
				classification: class_id,
				authenticity_token: csrf
			}, function (data) {
				clear_selected_events();
				$.getScript(baseuri + '/events/sessions?direction=' + direction + '&sort=' + sort + '&page=' + current_page_number);

				flash_message.push({
					type: 'success',
					message: "Event(s) Classified Successfully (" + count + " sessions)"
				});
			});

		} else {
			classify_events();
		}

	} else {

		if ($('ul.table div.content li.event.currently-over.highlight').is(':visible')) {

			$('ul.table div.content li.event.currently-over.highlight .row div.select input#event-selector').click().trigger('change');
			set_classification(class_id);

		} else {

			flash_message.push({type: 'error', message: "Please Select Events To Perform This Action"});
			flash();
			$.scrollTo('#header', 500);
		}
	}
}

function fetch_last_event(callback) {
	$.ajax({
		url: baseuri + '/events/last',
		dataType: 'json',
		type: 'GET',
		global: false,
		cache: false,
		success: function (data) {
			if (data && (data.time)) {
				$('div#wrapper').attr({last_event: data.time});
				callback(data.time);
			}
		}
	});
}

function monitor_events(prepend_events) {

	$("#growl").notify({
		speed: 500,
		expires: 5000
	});

	fetch_last_event(function (time) {
		setInterval(function () {
			new_event_check(prepend_events);
		}, 50000);
	});
}

function new_event_check(prepend_events) {
	$.ajax({
		url: baseuri + '/events/last',
		dataType: 'json',
		type: 'GET',
		global: false,
		cache: false,
		success: function (data) {
			var old_id = $('div#wrapper').attr('last_event');

			var page = parseInt($('.pager li.active a').html());

			if (old_id != data.time) {
				$.ajax({
					url: baseuri + '/events/since',
					data: {timestamp: old_id},
					dataType: 'json',
					type: 'GET',
					global: false,
					cache: false,
					success: function (newEvents) {
						if (newEvents.events && newEvents.events.length != 0) {

							if (prepend_events) {
								if (page <= '1') {

									if ($('div.new_events').length == 0) {

										$('#events').prepend('<div class="note new_events"><strong class="new_event_count">' + newEvents.events.length + '</strong> New Events Are Available Click here To View Them.</div>');

									} else {

										var new_count = parseInt($('#events div.new_events strong.new_event_count').html()) + newEvents.events.length;
										$('#events div.new_events').html('<strong class="new_event_count">' + new_count + '</strong> New Events Are Available Click here To View Them.');

									}

									$('#events ul.table div.content').prepend(Bricata.templates.event_table(newEvents));
								}
							}

							Bricata.notification({
								title: 'New Events',
								text: newEvents.events.length + ' Events Added.'
							});
						}
					}
				});

				$('div#wrapper').attr('last_event', data.time);
			}
		}
	});
}

function update_note_count(event_id, data) {

	var event_row = $('li#' + event_id + ' div.row div.timestamp');
	var notes_count = event_row.find('span.notes-count');

	var template = '<span class="add_tipsy round notes-count" title="{{notes_count_in_words}}"><img alt="Notes" height="16" src="' + baseuri + '/images/icons/notes.png" width="16"></span>'
	var event_html = Bricata.templates.render(template, data);

	if (data.notes_count == 0) {

		notes_count.remove();

	} else {

		if (notes_count.length > 0) {
			notes_count.replaceWith(event_html).trigger('tipsy.reload');
		} else {
			event_row.prepend(event_html).trigger('tipsy.reload');
		}
	}
}

var Bricata = {

	file: {
		upload_asset_csv: function () {
			var self = $('#bulk-upload-form');
			self.submit();
		}
	},

	submitAssetName: function () {
		var self = $('form.update-asset-name-form');
		var q = self.formParams();
		var params = {};
		var errors = 0;

		$('button.update-asset-name-submit-button').attr('disabled', true).find('span').text('Loading...');

		if (q.id) {
			params.id = q.id;
		}

		if (q.ip_address) {
			params.ip_address = q.ip_address;
		} else {
			errors++;
		}

		if (q.name) {
			params.name = q.name;
		} else {
			errors++;
			$('input#edit-asset-name-title').addClass('error');
		}

		if (q.global) {
			params.global = true;
		} else {
			params.global = false;
			if (q.agents) {
				params.sensors = q.agents;
			} else {
				errors++;
				$('#edit-asset-name-agent-select_chzn .chzn-choices').addClass('error');
			}
		}

		if (Bricata.submitAjaxRequestAssetName) {
			Bricata.submitAjaxRequestAssetName.abort();
		}

		if (errors <= 0) {
			Bricata.submitAjaxRequestAssetName = $.ajax({
				url: baseuri + '/asset_names/add',
				dataType: "json",
				data: params,
				type: "post",
				success: function (data) {
					$.limpClose();
					var agent_ids = [];

					for (var i = 0; i < data.asset_name.sensors.length; i += 1) {
						agent_ids.push(parseInt(data.asset_name.sensors[i]));
					}

					$('#asset-names .asset-names [data-asset-id]').each(function () {
						var address_name = $(this).find('.asset-name');
						var agents = $(this).find('.asset-agents');
						var addr = $(this).find('.asset-address').text().trim();
						var id = parseInt($(this).attr('data-asset-id'));
						var edit_asset_name = $(this).find('.edit-asset-name')

						if (addr === data.asset_name.ip_address) {
							if (data.asset_name.global){
								agents.text('All Agents');
							}else{
								if (agent_ids.length === 1) {
									agents.text('1 Agent');
								} else {
									agents.text(agent_ids.length + ' Agents');
								}
							}
							address_name.text(data.asset_name.name);
							edit_asset_name.attr('data-asset_agent_ids', agent_ids);
							edit_asset_name.attr('data-asset_global', data.asset_name.global);
							edit_asset_name.attr('data-asset_name', data.asset_name.name);
						}
					});
				},
				error: function (a, b, c) {
					$('button.update-asset-name-submit-button').attr('disabled', false).find('span').text('Update');
					flash_message.push({
						type: 'error',
						message: "Error: " + c
					});
					flash();
				}
			});
		} else {
			$('button.update-asset-name-submit-button').attr('disabled', false).find('span').text('Update');
			flash_message.push({
				type: 'error',
				message: "Please make sure all form fields are correctly populated."
			});
			flash();
		}
	},

	sessionViewUpdate: function (params, timeout) {
		var delay = timeout || 20000;

		Bricata.sessionViewUpdateClear();

		Bricata.sessionViewUpdateInterval = setInterval(function () {
			if (Bricata.sessionViewUpdateRequest) {
				Bricata.sessionViewUpdateRequest.abort();
			}

			Bricata.sessionViewUpdateRequest = $.ajax({
				url: baseuri + '/events/sessions.json',
				data: {
					sort: params.sort || 'desc',
					direction: params.direction || 'timestamp',
					page: params.page || 0
				},
				global: false,
				type: 'get',
				dataType: 'json',
				success: function (data) {
					if (data.hasOwnProperty('events')) {
						var sessionCount = [];
						for (var i = 0; i < data.events.length; i += 1) {
							var event = data.events[i],
								row = $('li.event[data-session-id="' + event.ip_src + '_' + event.ip_dst + '_' + event.sig_id + '"]');

							if (row.length > 0) {
								if (parseInt(row.find('div.session-count').attr('data-sessions')) !== event.session_count) {
									var selector = 	row.find('div.session-count');
									
									selector.attr('data-sessions', event.session_count)
										.find('span')
										.html(event.session_count)
										.removeClass('grey')
										.addClass('yellow');

									sessionCount.push(selector.find('span'));

									setTimeout(function(){
										$(sessionCount).each(function(){$(this).removeClass('yellow').addClass('grey')});
									}, 2000);

									row.find('div.timestamp b')
										.attr('title', "Event ID: " + event.sid + "." + event.cid + " " + event.datetime)
										.html(event.timestamp);
								}
							} else {
								if (parseInt(params.page) < 1) {
									var html = Bricata.puts('session-event-row', event);
									$('div#events ul.table div.content').prepend(html);
								}
							}
						} // for loop
						// $('div#events ul.table div.content li').sortElements(function(a, b) {
						// });
					}
				}
			});
		}, delay);
	},

	sessionViewUpdateClear: function () {
		if (Bricata.sessionViewUpdateInterval) {
			clearInterval(Bricata.sessionViewUpdateInterval);
		}

		if (Bricata.sessionViewUpdateRequest) {
			Bricata.sessionViewUpdateRequest.abort();
		}
	},

	colorPicker: function () {

		$('#severity-color-bg').ColorPicker({
			color: $('#severity-color-bg').val(),
			onShow: function (colpkr) {
				$(colpkr).fadeIn(500);
				return false;
			},
			onHide: function (colpkr) {
				$(colpkr).fadeOut(500);
				return false;
			},
			onSubmit: function (hsb, hex, rgb, el) {
				$(el).ColorPickerHide();
			},
			onChange: function (hsb, hex, rgb) {
				$('#severity-color-bg').val('#' + hex);
				$('span.severity').css('backgroundColor', '#' + hex);
			}
		});

		$('#severity-color-text').ColorPicker({
			color: $('#severity-color-text').val(),
			onShow: function (colpkr) {
				$(colpkr).fadeIn(500);
				return false;
			},
			onHide: function (colpkr) {
				$(colpkr).fadeOut(500);
				return false;
			},
			onSubmit: function (hsb, hex, rgb, el) {
				$(el).ColorPickerHide();
			},
			onChange: function (hsb, hex, rgb) {
				$('#severity-color-text').val('#' + hex);
				$('span.severity').css('color', '#' + hex);
			}
		});
	},


	bricataCloudBoxOptions: {
		cache: true,
		round: 5,
		loading: true,
		animation: 'none',
		distance: 10,
		overlayClick: true,
		enableEscapeButton: true,
		dataType: 'html',
		centerOnResize: true,
		closeButton: true,
		shadow: '0 0 30px rgba(0,0,0,1)',
		style: {
			background: 'rgba(36,36,36,0.9)',
			border: '1px solid rgba(0,0,0,0.9)',
			padding: '0',
			width: '700px'
		},
		inside: {
			background: 'transparent',
			padding: '0',
			display: 'block',
			border: 'none',
			overflow: 'visible'
		},
		overlay: {
			background: '#000',
			opacity: 0.9
		},
		onOpen: function () {
			// disable_scroll();
			// if (Bricata.escBind) {
			// $(document).unbind('keydown', Bricata.escBind);
			// };
			$('body').addClass('stop-scrolling');
			$('body').bind('touchmove', function (e) {
				e.preventDefault();
			});

			$('dl#event-sub-menu').hide();
		},
		afterOpen: function (limp, html) {
			Bricata.eventCloseHotkeys(false);
			// $('.add-chosen').chosen();
			// $(".add-chosen").trigger("liszt:updated");
			if (Bricata.escBind) {
				$(document).unbind('keydown', Bricata.escBind);
			}

			html.find('#bricatabox-content .add_chosen').chosen({
				allow_single_deselect: true
			});

			Bricata.colorPicker();

			$('img.recover, img.avatar, img.user-view-avatar, img.avatar-small, div.note-avatar-holder img').error(function (event) {
				$(this).attr("src", baseuri + "/images/default_avatar.png");
			});
		},
		afterClose: function () {
			Bricata.eventCloseHotkeys(true);

			if (Bricata.escBind) {
				$(document).bind('keydown', 'esc', Bricata.escBind);
			}

			// enable_scroll();
			$('body').removeClass('stop-scrolling');
			$('body').unbind('touchmove')
		},
		onTemplate: function (template, data, limp) {

			try {
				var $html = Bricata.puts(template, data);
				if ($html.length > 0) {
					return $html;
				}
				return false;
			} catch (e) {
				return false;
			}

		}
	},

	puts: function (name, data) {
		var self = this;

		if (Handlebars.templates.hasOwnProperty(name)) {
			var $html = $(Handlebars.templates["" + name + ""](data));
		} else {
			var template = Handlebars.compile(name);
			var $html = template(data);
		}
		return $html;
	},

	box: function (template, data, args) {
		var self = this;

		$.limpClose();
		var options = $.extend({}, self.bricataCloudBoxOptions, args);
		options.template = template;
		options.templateData = data;

		return $.limp(options);
	},

	setup: function () {

		$('div#flash_message, div#flash_message > *').on('click', function () {
			$('div#flash_message').stop().fadeOut('fast');
		});

		$("#growl").notify({
			speed: 500,
			expires: 5000
		});

		$('.edit-sensor-name').editable(baseuri + "/sensors/update_name", {
			height: '20px', width: '140px', name: "name",
			indicator: '<img src="' + baseuri + '/images/icons/pager.gif">',
			data: function (value) {
				var retval = value.replace(/<br[\s\/]?>/gi, '\n');
				return retval;
			},
			submitdata: function () {
				return {id: $(this).attr('data-sensor-id'), authenticity_token: csrf};
			}
		});

	},

	pages: {

		classifications: function () {
			$('a.classification').on('click', function () {
				var class_id = $(this).attr('data-classification-id');
				set_classification(class_id);
				return false;
			});
		},

		dashboard: function () {

			$('#box-holder div.box').on('click', function (e) {
				//e.preventDefault();
				window.location = $(this).attr('data-url');
				return false;
			});

			$('a.show_events_graph').on('click', function (e) {
				var selector = $('#box-tabs1');
				selector.find('span').text($(this).text()).append('<span class="glyphicon glyphicon-triangle-bottom" aria-hidden="true"></span>');
				$(selector).find('li').removeClass('active');
				$(this).parent('li').addClass('active');
				selector.removeClass('open');

				$('div.dashboard-graph').hide();
				$('div#events-graph').show();
				return false;
			});

			$('a.show_severities_graph').on('click', function (e) {
				var selector = $('#box-tabs1');
				selector.find('span').text($(this).text()).append('<span class="glyphicon glyphicon-triangle-bottom" aria-hidden="true"></span>');
				$(selector).find('li').removeClass('active');
				$(this).parent('li').addClass('active');
				selector.removeClass('open');

				$('div.dashboard-graph').hide();
				$('div#severity-graph').show();
				return false;
			});

			$('a.show_protocol_graph').on('click', function (e) {
				var selector = $('#box-tabs1');
				selector.find('span').text($(this).text()).append('<span class="glyphicon glyphicon-triangle-bottom" aria-hidden="true"></span>');
				$(selector).find('li').removeClass('active');
				$(this).parent('li').addClass('active');
				selector.removeClass('open');

				$('div.dashboard-graph').hide();
				$('div#protocol-graph').show();
				return false;
			});

			//$('a.show_map_graph').on('click', function(e) {
			//   loadSelectedItem($('#box-tabs1'));
			//	//e.preventDefault();
			//	//$('#box-menu li').removeClass('active');
			//	//$(this).parent('li').addClass('active');
			//	$('div.dashboard-graph').hide();
			//	$('div#geoip-graph').show();
			//	return false;
			//});

			//$('a.show_signature_graph').on('click', function(e) {
			//	e.preventDefault();
			//	$('#box-menu li').removeClass('active');
			//	$(this).parent('li').addClass('active');
			//	$('div.dashboard-graph').hide();
			//	$('div#signature-graph').show();
			//	return false;
			//});

			//$('a.show_classification_graph').on('click', function(e) {
			// loadSelectedItem($('#box-tabs1'));
			//	//e.preventDefault();
			//	//$('#box-menu li').removeClass('active');
			//	//$(this).parent('li').addClass('active');
			//	$('div.dashboard-graph').hide();
			//	$('div#classification-graph').show();
			//	return false;
			//});

			//$('a.show_source_ips_graph').on('click', function(e) {
			//	e.preventDefault();
			//	$('#box-menu li').removeClass('active');
			//	$(this).parent('li').addClass('active');
			//	$('div.dashboard-graph').hide();
			//	$('div#source-ips-graph').show();
			//	return false;
			//});
			//
			//$('a.show_destination_ips_graph').on('click', function(e) {
			//	e.preventDefault();
			//	$('#box-menu li').removeClass('active');
			//	$(this).parent('li').addClass('active');
			//	$('div.dashboard-graph').hide();
			//	$('div#destination-ips-graph').show();
			//	return false;
			//});

		},

		events: function () {

			var body = $('body');
			body.on('change', 'select.email-user-select', function (e) {
				var email = $('select.email-user-select').val();

				if (email != '') {
					if ($('input#email_to').val() == '') {
						$('input#email_to').val(email);
					} else {
						$('input#email_to').val($('input#email_to').val() + ', ' + email);
					}
				}
			});

			body.on('click', 'button.email-event-information', function (e) {
				e.preventDefault();
				if ($('input#email_to').val() == '') {
					flash_message.push({type: 'error', message: "The email recipients cannot be blank."});
					flash();
					$.scrollTo('#header', 500);
				} else {
					if ($('input#email_subject').val() == '') {
						flash_message.push({type: 'error', message: "The email subject cannot be blank."});
						flash();
						$.scrollTo('#header', 500);
					} else {
						$(document).trigger('limp.close');
						if (!window.location.origin) {
							window.location.origin =
								window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
						}
						var input = $("<input>").attr("type", "hidden").attr("name", "hosturl").val(window.location.origin);
						$('form.email-event-information').append($(input));
						$.post(baseuri + '/events/email', $('form.email-event-information').serialize(), null, "script");
					}
				}
				return false;
			});

			body.on('click', 'button.request_packet_capture', function (e) {
				e.preventDefault();
				if ($(this).attr('data-deepsee')) {
					$('form.request_packet_capture input#method').val('deepsee')
				}
				$.post(baseuri + '/events/request_packet_capture', $('form.request_packet_capture').serialize(), null, "script");
				return false;
			});

			body.on('click', 'dl#event-sub-menu a', function (e) {
				$('dl#event-sub-menu').hide();
			});

            body.on('click', 'a.has-event-menu',function (e) {
				e.preventDefault();
				var menu = $(this).parent().find('dl.event-sub-menu');
				if (menu.css('display') !== 'none') {
					menu.fadeOut('fast')
				} else {
					$('dl.event-sub-menu').hide();
					menu.fadeIn('fast')
				}
				return false;
            });

			body.on('click', 'dl.event-sub-menu dd a',function (event) {
				$(this).parents('dl').fadeOut('fast');
			});

			body.on('click', 'button.mass-action', function (e) {
				e.preventDefault();
				var nform = $('form#mass-action-form');
				$(document).trigger('limp.close');
				$.post(baseuri + '/events/mass_action', nform.serialize(), null, "script");
				return false;
			});

			$(body).on('click', 'button.create-notification', function (e) {
				e.preventDefault();
				var nform = $('form#new_notification');
				$.post(baseuri + '/notifications', nform.serialize(), null, "script");
				$(document).trigger('limp.close');
				return false;
			});

			body.on('click', 'button.cancel-bricatabox', function (e) {
				e.preventDefault();
				$(document).trigger('limp.close');
				return false;
			});

			body.on('click', 'button.cancel-snorbybox', function (e) {
				e.preventDefault();
				window.history.back();
				location.reload();
				return false;
			});

			body.on('click', 'ul.payload-tabs li a', function (e) {
				e.preventDefault();

				var div_class = $(this).attr('data-div');

				$(this).parents('ul').find('li').removeClass('current');
				$(this).parent('li').addClass('current');
				$('div.payload-holder').hide();

				$('div.' + div_class + ' pre').css('opacity', 0);

				$('div.' + div_class).show();

				$('div.' + div_class + ' pre').stop().animate({"opacity": 1}, 1000);

				return false;
			});


			body.on('click', 'a.export', function (e) {
				e.preventDefault();
				var selected_events = $('input#selected_events').val();

				if (selected_events) {

					$.post(this.href, {events: selected_events, authenticity_token: csrf});

				} else {
					flash_message.push({type: 'error', message: "Please Select Events To Perform This Action"});
					flash();
				}

				return false;
			});

			body.on('click', 'a.edit-event-note', function (e) {
				e.preventDefault();
				var note = $(this).parents('div.event-note');
				var note_id = $(this).attr('data-note-id');
				$.getScript(baseuri + '/notes/' + note_id + '/edit');
				return false;
			});

			body.on('click', 'a.destroy-event-note', function (e) {
				e.preventDefault();
				var note = $(this).parents('div.event-note');
				var note_id = $(this).attr('data-note-id');

				if (confirm("Are you sure you want to delete this note?")) {
					$('div.notes').fadeTo(500, 0.4);
					$.post(baseuri + '/notes/destroy', {
						id: note_id,
						authenticity_token: csrf,
						'_method': 'delete'
					}, null, 'script');
				}

				return false;
			});

			body.on('click', 'button.add_new_note-working', function (e) {
				e.preventDefault();
				return false;
			});

			body.on('click', 'button.cancel-note', function (e) {
				e.preventDefault();
				$(this).parents('div#new_note_box').remove();
				return false;
			});

			body.on('click', 'button.add_new_note', function (e) {
				e.preventDefault();
				var event_sid = $(this).parent('div#form-actions').parent('div#new_note').attr('data-event-sid');
				var event_cid = $(this).parent('div#form-actions').parent('div#new_note').attr('data-event-cid');

				if ($('div#new_note_box').length > 0) {

				} else {
					$(this).removeClass('add_new_note').addClass('add_new_note-working');

					var current_width = $(this).width();
					$(this).addClass('loading').css('width', current_width);

					$.get(baseuri + '/notes/new', {
						sid: event_sid,
						cid: event_cid,
						authenticity_token: csrf
					}, null, 'script');
				}

				return false;
			});

			body.on('click', 'button.submit_new_note', function (e) {
				e.preventDefault();
				var event_sid = $(this).parent('div#form-actions').parent('div#new_note').attr('data-event-sid');
				var event_cid = $(this).parent('div#form-actions').parent('div#new_note').attr('data-event-cid');
				var note_body = $(this).parent('div#form-actions').parent('div#new_note').find('textarea#body').val();

				if (note_body.length > 0) {

					var current_width = $(this).width();
					$(this).addClass('loading').css('width', current_width);

					$.post(baseuri + '/notes/create', {
						sid: event_sid,
						cid: event_cid,
						body: note_body,
						authenticity_token: csrf
					}, null, 'script');

				} else {
					flash_message.push({type: "error", message: "The note body cannot be blank!"});
					flash();
					$.scrollTo('#header', 500);
				}

				return false;
			});

			body.on('click', 'a.query-data', function () {
				$('pre.query-data-content').hide();
				$('pre#' + $(this).attr('data-content-name')).show();
				return false;
			});

			$('.bricatabox').limp({
				cache: true,
				round: 0,
				loading: true,
				animation: 'pop',
				enableEscapeButton: true,
				shadow: '0 1px 30px rgba(0,0,0,0.6)',
				style: {
					background: 'rgba(36,36,36,0.9)',
					border: '1px solid rgba(0,0,0,0.9)',
					padding: '5px',
					width: '700px'
				},
				inside: {
					border: '1px solid rgba(0,0,0,0.9)',
					padding: 0
				},
				overlay: {
					background: '#000',
					opacity: 0.6
				},
				onOpen: function () {
					Bricata.eventCloseHotkeys(false);
					body.addClass('stop-scrolling');
					body.bind('touchmove', function (e) {
						e.preventDefault();
					});
					$('dl#event-sub-menu').hide();
				},
				afterOpen: function (limp, html) {

					html.find('#bricatabox-content .add_chosen').chosen({
						allow_single_deselect: true
					});
				},
				onClose: function () {
					Bricata.eventCloseHotkeys(true);
				},
				afterClose: function () {
					Bricata.eventCloseHotkeys(true);

					if (Bricata.escBind) {
						$(document).bind('keydown', 'esc', Bricata.escBind);
					}

					// enable_scroll();
					body.removeClass('stop-scrolling');
					body.unbind('touchmove')
				}
			});

			body.on('click', 'div.create-favorite.enabled', function () {
				var sid = $(this).parents('li.event').attr('data-event-sid');
				var cid = $(this).parents('li.event').attr('data-event-cid');

				$(this).removeClass('create-favorite').addClass('destroy-favorite');
				$.post(baseuri + '/events/favorite', {sid: sid, cid: cid, authenticity_token: csrf});

				var count = new Queue();
				count.up();

				return false;
			});

			body.on('click','div.destroy-favorite.enabled', function () {
				var sid = $(this).parents('li.event').attr('data-event-sid');
				var cid = $(this).parents('li.event').attr('data-event-cid');
				var action = $('div#events').attr('data-action');

				$(this).removeClass('destroy-favorite').addClass('create-favorite');
				$.post(baseuri + '/events/favorite', {sid: sid, cid: cid, authenticity_token: csrf});

				var count = new Queue();
				count.down();

				if (action == 'queue') {
					$('div.content').fadeTo(500, 0.4);
					Bricata.helpers.remove_click_events(true);
					$('div.destroy-favorite').removeClass('enabled').css('cursor', 'default');
					$.get(baseuri + '/events/queue', null, null, "script");
				}

				return false;
			});

			body.on('change', 'input.event-select-all', function () {
				var $item = $('ul.table div.content li.event input#event-selector');

				if ($(this).is(':checked')) {
					$item.prop('checked', true);
					$item.trigger('change');
				} else {
					$item.prop('checked', false);
					$item.trigger('change');
				}

			});

			body.on('click', 'ul.table div.content li.event div.click', function () {
				var self = $(this);

				$('dl#event-sub-menu').hide();

				var sid = $(this).parents('li').attr('data-event-sid');
				var cid = $(this).parents('li').attr('data-event-cid');
				var parent_row = $('li#event_' + sid + '' + cid);
				var check_box = $('li#event_' + sid + '' + cid + ' input#event-selector');

				var current_row = $('li#event_' + sid + '' + cid + ' div.event-data');

				Bricata.helpers.remove_click_events(true);
				$('li.event').removeClass('highlight');

				if (!current_row.is(':visible')) {
					parent_row.addClass('highlight');
				} else {
					parent_row.removeClass('highlight');
				}

				if (current_row.attr('data') == 'true') {
					Bricata.helpers.remove_click_events(false);

					if (current_row.is(':visible')) {

						current_row.slideUp('fast', function () {
							$('li.event div.event-data').slideUp('fast');
							Bricata.eventCloseHotkeys(true);
						});

					} else {
						$('li.event div.event-data').slideUp('fast');
						current_row.slideDown('fast', function () {

							$(document).bind('keydown', 'esc', function () {
								$('li.event').removeClass('highlight');
								parent_row.removeClass('highlight');

								current_row.slideUp('fast', function () {
									$('li.event div.event-data').slideUp('fast');
								});

								Bricata.eventCloseHotkeys(true);
								$(this).unbind('keydown', 'esc');
							});

							Bricata.eventCloseHotkeys(false);
						});
					}

				} else {

					check_box.hide();
					$('li.event div.event-data').slideUp('fast');
					parent_row.find('div.select').append("<img alt='loading' src='" + baseuri + "/images/icons/loading.gif' class='select-loading'>");

					var open_event_url = baseuri + '/events/show/' + sid + '/' + cid;

					if ($('div#events').data('action') === "sessions") {
						open_event_url = baseuri + '/events/show/' + sid + '/' + cid + '?sessions=true';
					}

					$.get(open_event_url, function () {

						$(document).bind('keydown', 'esc', function () {
							$('li.event').removeClass('highlight');
							parent_row.removeClass('highlight');

							current_row.slideUp('fast', function () {
								$('li.event div.event-data').slideUp('fast');
							});

							$(this).unbind('keydown', 'esc');
							Bricata.eventCloseHotkeys(true);
						});

						Bricata.helpers.remove_click_events(false);

						$('.select-loading').remove();
						check_box.show();
						current_row.attr('data', true);

						Bricata.eventCloseHotkeys(false);
					}, 'script');

				}

				return false;
			});

			body.on('click', 'div.new_events', function () {
				$(this).remove();
				if (parseInt($('strong.new_event_count').html()) > 100) {
					window.location = baseuri + '/events'
				} else {
					$('#events ul.table div.content li').fadeIn('slow');
				}
				return false;
			});

		}

	},

	eventCloseHotkeys: function (bind) {
		if (bind) {
			$(document).bind('keydown', '1', Bricata.hotKeyCallback.Sev1);
			$(document).bind('keydown', '2', Bricata.hotKeyCallback.Sev2);
			$(document).bind('keydown', '3', Bricata.hotKeyCallback.Sev3);

			$(document).bind('keydown', 'shift+right', Bricata.hotKeyCallback.shiftPlusRight);
			$(document).bind('keydown', 'right', Bricata.hotKeyCallback.right);
			$(document).bind('keydown', 'shift+left', Bricata.hotKeyCallback.shiftPlusLeft);
			$(document).bind('keydown', 'left', Bricata.hotKeyCallback.left);
		} else {

			$(document).unbind('keydown', Bricata.hotKeyCallback.Sev1);
			$(document).unbind('keydown', Bricata.hotKeyCallback.Sev2);
			$(document).unbind('keydown', Bricata.hotKeyCallback.Sev3);

			$(document).unbind('keydown', Bricata.hotKeyCallback.shiftPlusRight);
			$(document).unbind('keydown', Bricata.hotKeyCallback.right);
			$(document).unbind('keydown', Bricata.hotKeyCallback.shiftPlusLeft);
			$(document).unbind('keydown', Bricata.hotKeyCallback.left);
		}
	},

	admin: function () {

		$('#users input#enabled').on('click', function (e) {
			var user_id = $(this).parent('td').attr('data-user');
			if (this.checked) {
				$.post(baseuri + '/users/toggle_settings', {
					user_id: user_id,
					user: {enabled: true},
					authenticity_token: csrf
				});
			} else {
				$.post(baseuri + '/users/toggle_settings', {
					user_id: user_id,
					user: {enabled: false},
					authenticity_token: csrf
				});
			}
		});

		$('#users input#admin').on('click', function (e) {
			var user_id = $(this).parent('td').attr('data-user');
			if (this.checked) {
				$.post(baseuri + '/users/toggle_settings', {
					user_id: user_id,
					user: {admin: true},
					authenticity_token: csrf
				});
			} else {
				$.post(baseuri + '/users/toggle_settings', {
					user_id: user_id,
					user: {admin: false},
					authenticity_token: csrf
				});
			}
			;
		});

		$('#severity-color-bg').ColorPicker({
			color: $('#severity-color-bg').val(),
			onShow: function (colpkr) {
				$(colpkr).fadeIn(500);
				return false;
			},
			onHide: function (colpkr) {
				$(colpkr).fadeOut(500);
				return false;
			},
			onSubmit: function (hsb, hex, rgb, el) {
				$(el).ColorPickerHide();
			},
			onChange: function (hsb, hex, rgb) {
				$('#severity-color-bg').val('#' + hex);
				$('span.severity').css('backgroundColor', '#' + hex);
			}
		});

		$('#severity-color-text').ColorPicker({
			color: $('#severity-color-text').val(),
			onShow: function (colpkr) {
				$(colpkr).fadeIn(500);
				return false;
			},
			onHide: function (colpkr) {
				$(colpkr).fadeOut(500);
				return false;
			},
			onSubmit: function (hsb, hex, rgb, el) {
				$(el).ColorPickerHide();
			},
			onChange: function (hsb, hex, rgb) {
				$('#severity-color-text').val('#' + hex);
				$('span.severity').css('color', '#' + hex);
			}
		});
	},

	templates: {

		render: function (source, data) {
			var self = this;

			var template = Handlebars.compile(source);
			return template(data);
		},

		flash: function (data) {
			var self = this;

			var template = " \
			<div class='{{type}}' id='flash_message' style='display:none;'> \
				<div class='message {{type}}'>{{message}}</div> \
			</div>";
			return Bricata.templates.render(template, data);
		},

		event_table: function (data) {
			var self = this;

			var klass = '';
			if (data.events[0].geoip) {
				klass = ' geoip'
			}

			var template = " \
			{{#events}} \
			<li id='event_{{sid}}{{cid}}' class='event' style='display:none;' data-event-id='{{sid}}-{{cid}}' data-event-sid='{{sid}}' data-event-cid='{{cid}}'> \
				<div class='row" + klass + "'> \
					<div class='select small'><input class='event-selector' id='event-selector' name='event-selector' type='checkbox'></div> \
					<div class='important small'><div class='create-favorite enabled'></div></div> \
					<div class='severity small'><span class='severity sev{{severity}}'>{{severity}}</span></div> \
					<div class='click sensor'>{{hostname}}</div> \
          <div class='click src_ip address'> \
            {{{geoip this.src_geoip}}} {{ip_src}} \
          </div> \
					<div class='click dst_ip address'> \
            {{{geoip this.dst_geoip}}} {{ip_dst}} \
          </div> \
					<div class='click signature'>{{message}}</div> \
					<div class='click timestamp'> \
            <b class='add_tipsy' title='Event ID: {{sid}}.{{cid}} &nbsp; {{datetime}}'>{{timestamp}}</b> \
          </div> \
				</div> \
				<div style='display:none;' class='event-data' data='false'></div> \
			</li> \
			{{/events}}";

			return Bricata.templates.render(template, data);
		},

		update_notifications: function (data) {
			var self = this;
			var template = '<div id="update-notification">' +
				'<span>' +
				'<div class="message-update-notification">' +
				'A new version of Bricata is now avaliable. ' +
				'</div>' +
				'Version {{version}} - ' +
				'' +
				'<a href="{{download}}" target="_blank">Download</a>  - ' +
				'<a href="{{changeLog}}" target="_blank">Change Log</a>' +
				'' +
				'<div class="close-update-notification">x</div>' +
				'</span>' +
				'</div>';

			$('div.close-update-notification').on('click', function (e) {
				e.preventDefault();
				$.cookie('bricata-ignore-update', 1, {expires: 20});
				$('div#update-notification').remove();
			});

			return Bricata.templates.render(template, data);
		},

		searchLoading: function () {
			var self = this;
			var template = '<div class="search-loading" />';
			return template;
		},

		signatureTable: function () {
			var self = this;
			var template = '<div id="signatures-input-search" class="grid_12 page boxit" style="display: block;">' +
				'<table class="default" border="0" cellspacing="0" cellpadding="0">' +
				'<tbody><tr><th style="width:30px">Sev.</th><th>Signature Name</th><th>Event Count</th><th></th></tr></tbody>' +
				'<tbody class="signatures content">' +
				'</tbody>' +
				'</table>' +
				'</div>';

			return template;
		},

		signatures: function (data) {
			var self = this;
			var event_count = data.total;

			var template = '{{#each signatures}}' +
				'<tr>' +
				'<td class="first">' +
				'<div class="severity small">' +
				'<span class="severity sev{{sig_priority}}">' +
				'{{sig_priority}}' +
				'</span>' +
				'</div>' +
				'</td>' +
				'<td class="" title="{{sig_name}}">' +
				'{{{truncate this.sig_name 60}}}' +
				'</td>' +
				'<td class="chart-large add_tipsy" original-title="{{events_count}} of {{../total}} events">' +
				'<div class="progress-container-large">' +
				'<div style="width: {{{percentage ../total}}}%">' +
				'<span>{{{percentage ../total}}}%</span>' +
				'</div>' +
				'</div>' +
				'</td>' +
				'<td class="last" style="width:45px;padding-right:6px;padding-left:0px;">' +
				'<a href="results?match_all=true&search%5Bsignature%5D%5Bcolumn%5D=signature&search%5Bsignature%5D%5Boperator%5D=is&search%5Bsignature%5D%5Bvalue%5D={{sig_id}}&title={{sig_name}}">View</a>' +
				'</td>' +
				'</tr>{{/each}}';
			return Bricata.templates.render(template, data);
		}

	},

	notification: function (message) {
		$('#growl').notify("create", message, {
			expires: 3000,
			speed: 500
		});
	},

	helpers: {

		tipsy: function () {

			$('.add_tipsy').tipsy({
				fade: true,
				html: false,
				gravity: 's',
				live: true
			});

			$('.add_tipsy_html').tipsy({
				fade: true,
				html: true,
				gravity: 's',
				live: true
			});

		},

		input_style: function () {

			$('div#form-actions button.cancel').on('click', function () {
				window.location = baseuri + '/';
				return false;
			});

			$('input[name=blank]').focus();

		},

		dropdown: function () {

			$(document).click(function () {
				$('dl.drop-down-menu:visible').hide();
			});

			$('dl.drop-down-menu dd a').on('click', function () {
				$('dl.drop-down-menu').fadeOut('slow');
				return true;
			});

			$('dl.drop-down-menu').hover(function () {
				var timeout = $(this).data("timeout");
				if (timeout) clearTimeout(timeout);
			}, function () {
				$(this).data("timeout", setTimeout($.proxy(function () {
					$(this).fadeOut('fast');
				}, this), 500));
			});

			$('a.has_dropdown').on('click', function () {

				var id = $(this).attr('id');
				var dropdown = $(this).parents('li').find('dl#' + id);

				$('dl.drop-down-menu').each(function (index) {

					if (id === $(this).attr('id')) {

						if ($(this).is(':visible')) {
							dropdown.fadeOut('fast');
						} else {
							dropdown.slideDown({
								duration: 'fast',
								easing: 'easeOutSine'
							});
						}

					} else {
						$(this).fadeOut('fast')
					}

				});
				return false;
			});
		},

		persistence_selections: function () {

			$('body').on('change', 'input#event-selector', function () {

				var event_id = $(this).parents('li').attr('data-event-id');

				var sessions = false;
				if ($('#events').data('action') === "sessions") {
					var sessions = true;
					if ($('div#sessions-event-count-selected').length == 0) {
						$('#content').append('<div id="sessions-event-count-selected" data-count="0" />');
					}

					var current_count = parseInt($('div#sessions-event-count-selected').data('count'));
				}

				var checked = $(this).is(':checked');

				if (checked) {

					selected_events.push(event_id);
					$('input#selected_events[type="hidden"]').val(selected_events);

				} else {

					var removeItem = event_id;
					selected_events = jQuery.grep(selected_events, function (value) {
						return value != removeItem;
					});

					$('input#selected_events[type="hidden"]').val(selected_events);
				}

				if (sessions) {
					var session_count = parseInt($(this).parents('li.event').find('div.session-count').data('sessions'));

					if (session_count) {
						var value = 0;

						if (checked) {
							value = current_count + session_count;
						} else {
							value = current_count - session_count;
						}

						$('div#sessions-event-count-selected').data('count', value);
					}
				}

			});

			$('body').on('change', 'input#event-select-all' ,function () {

				if (this.checked) {

					$('ul.table div.content li input[type="checkbox"]').each(function (index, value) {
						var event_id = $(this).parents('li').attr('data-event-id');
						$(this).prop('checked', true);
						selected_events.push(event_id);
					});

				} else {

					$('ul.table div.content li input[type="checkbox"]').each(function (index, value) {
						var removeItem = $(this).parents('li').attr('data-event-id');
						$(this).prop('checked', false);
						selected_events = jQuery.grep(selected_events, function (value) {
							return value != removeItem;
						});
					});
				}

				$('input#selected_events[type="hidden"]').val(selected_events);

			});

		},

		recheck_selected_events: function () {
			$('input#selected_events').val(selected_events);
			$.each(selected_events, function (index, value) {
				$('input.check_box_' + value).$(this).prop('checked', true);
			});
		},

		pagenation: function () {

			$('ul.pager li').on('click', function () {
				var self = this;

				var notes = $(this).parents('.pager').hasClass('notes-pager');

				if (history && history.pushState) {
					$(window).bind("popstate", function () {
						$.getScript(location.href);
					});
				}

				if (!$(self).hasClass('more')) {

					var current_width = $(self).width();
					if (current_width < 16) {
						var current_width = 16
					}

					$(self).addClass('loading').css('width', current_width);

					if ($(self).parents('div').hasClass('notes-pager')) {
						$('div.notes').fadeTo(500, 0.4);
					} else {
						$('div.content, tbody.content').fadeTo(500, 0.4);
					}

					Bricata.helpers.remove_click_events(true);

					if ($('div#search-params').length > 0) {

						var search_data = JSON.parse($('div#search-params').text());

						if (search_data) {
							$.ajax({
								url: $(self).find('a').attr('href'),
								global: false,
								dataType: 'script',
								data: {
									match_all: search_data.match_all,
									search: search_data.search,
									authenticity_token: csrf
								},
								cache: false,
								type: 'POST',
								success: function (data) {
									$('div.content').fadeTo(500, 1);
									Bricata.helpers.remove_click_events(false);
									Bricata.helpers.recheck_selected_events();

									if (!notes) {
										if (history && history.pushState) {
											history.pushState(null, document.title, $(self).find('a').attr('href'));
										}
										$.scrollTo('#header', 500);
									}
								}
							});
						}

					} else {
						$.getScript($(self).find('a').attr('href'), function () {
							$('div.content').fadeTo(500, 1);
							Bricata.helpers.remove_click_events(false);
							Bricata.helpers.recheck_selected_events();

							if (!notes) {
								if (history && history.pushState) {
									history.pushState(null, document.title, $(self).find('a').attr('href'));
								}
								$.scrollTo('#header', 500);
							}

						});
					}

				}

				return false;
			});

		},

		remove_click_events: function (hide) {
			if (hide) {
				$('ul.table div.content div').removeClass('click');
			} else {
				$('li.event div.sensor, li.event div.src_ip, li.event div.dst_ip, li.event div.signature, li.event div.timestamp').addClass('click');
			}
		}
	},

	callbacks: function () {

		$('body').ajaxError(function (event, xhr, ajaxOptions, thrownError) {

			$('div.content').fadeTo(500, 1);
			$('ul.table div.content li input[type="checkbox"]').prop('checked', false);
			Bricata.helpers.remove_click_events(false);

			if (xhr['status'] === 404) {
				flash_message.push({type: 'error', message: "The requested page could not be found."});
				flash();
			} else {
				flash_message.push({type: 'error', message: "The request failed to complete successfully."});
				flash();
			}

		});

	},

	hotKeyCallback: {

		left: function () {
			$('div.pager.main ul.pager li.previous a').click();
		},

		right: function () {
			$('div.pager.main ul.pager li.next a').click();
		},

		shiftPlusRight: function () {
			$('div.pager.main ul.pager li.last a').click();
		},

		shiftPlusLeft: function () {
			$('div.pager.main ul.pager li.first a').click();
		},

		Sev1: function () {
			$('span.sev1').parents('div.row').find('input#event-selector').each(function () {
				var $checkbox = $(this);
				$checkbox.prop('checked', !$checkbox.checked);
				$checkbox.trigger('change');
			});
		},

		Sev2: function () {
			$('span.sev2').parents('div.row').find('input#event-selector').each(function () {
				var $checkbox = $(this);
				$checkbox.prop('checked', !$checkbox.checked);
				$checkbox.trigger('change');
			});
		},

		Sev3: function () {
			$('span.sev3').parents('div.row').find('input#event-selector').each(function () {
				var $checkbox = $(this);
				$checkbox.prop('checked', !$checkbox.checked);
				$checkbox.trigger('change');
			});
		}

	},

	hotkeys: function () {
		var self = this;

		$(document).bind('keydown', 'ctrl+shift+h', function () {
			return false;
		});

		$(document).bind('keydown', 'ctrl+3', function () {
			window.location = baseuri + '/jobs';
			return false;
		});

		$(document).bind('keydown', 'ctrl+2', function () {
			window.location = baseuri + '/events';
			return false;
		});

		$(document).bind('keydown', 'ctrl+1', function () {
			window.location = baseuri + '/events/queue';
			return false;
		});

		$(document).bind('keydown', 'ctrl+shift+s', function () {
			window.location = baseuri + '/search';
			return false;
		});

		if ($('div.pager').is(':visible')) {

			$(document).bind('keydown', 'shift+down', function () {
				var item = $('ul.table div.content li.event.currently-over');

				if (item.is(':visible')) {
					if (item.next().length != 0) {
						item.removeClass('currently-over');
						item.next().addClass('currently-over');
					} else {
						$('ul.table div.content li.event:first').addClass('currently-over');
					}
				} else {
					$('ul.table div.content li.event:first').addClass('currently-over');
				}

			});

			$(document).bind('keydown', 'shift+up', function () {
				var item = $('ul.table div.content li.event.currently-over');
				if (item.is(':visible')) {
					if (item.prev().length != 0) {
						item.removeClass('currently-over');
						item.prev().addClass('currently-over');
					} else {
						$('ul.table div.content li.event:last').addClass('currently-over');
					}
				} else {
					$('ul.table div.content li.event:last').addClass('currently-over');
				}
			});

			$(document).bind('keydown', 'shift+return', function () {
				$('ul.table div.content li.event.currently-over div.row div.click').click();
			});

			$(document).bind('keydown', 'ctrl+shift+1', Bricata.hotKeyCallback.Sev1);
			$(document).bind('keydown', 'ctrl+shift+2', Bricata.hotKeyCallback.Sev2);
			$(document).bind('keydown', 'ctrl+shift+3', Bricata.hotKeyCallback.Sev3);
			$(document).bind('keydown', 'ctrl+shift+u', function () {
				set_classification(0);
			});

			$(document).bind('keydown', 'alt+right', function () {
				$('div.pager.notes-pager ul.pager li.next a').click();
			});

			$(document).bind('keydown', 'alt+left', function () {
				$('div.pager.notes-pager ul.pager li.previous a').click();
			});

			$(document).bind('keydown', 'ctrl+shift+a', function () {
				$('input.event-select-all').click().trigger('change');
			});

			Bricata.eventCloseHotkeys(true);

		}

	},

	validations: function () {

		jQuery.validator.addMethod("hex-color", function (value, element, param) {
			return this.optional(element) || /^#?([a-f]|[A-F]|[0-9]){3}(([a-f]|[A-F]|[0-9]){3})?$/i.test(value);
		}, jQuery.validator.messages.url);

		$('.validate').validate();

	},

	settings: function () {

		if ($('div#general-settings').length > 0) {

			if ($('input#_settings_packet_capture').is(':checked')) {
				$('div.pc-settings').show();
				$('p.pc-settings input[type="text"], p.pc-settings select').addClass('required');
			} else {
				$('div.pc-settings').hide();
				$('p.pc-settings input[type="text"], p.pc-settings select').removeClass('required');
			}

			if ($('input#_settings_packet_capture_auto_auth').is(':checked')) {
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').attr('disabled', null);
			} else {
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').attr('disabled', 'disabled');
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').removeClass('required');
			}

			var packet_capture_plugin = $('select#_settings_packet_capture_type').attr('packet_capture_plugin');

			$('select#_settings_packet_capture_type option[value="' + packet_capture_plugin + '"]').attr('selected', 'selected');

			if ($('input#_settings_autodrop').is(':checked')) {
				$('select#_settings_autodrop_count').attr('disabled', null);
			} else {
				$('select#_settings_autodrop_count').attr('disabled', 'disabled');
			}

			var autodrop_count = $('select#_settings_autodrop_count').attr('autodrop_count');
			$('select#_settings_autodrop_count option[value="' + autodrop_count + '"]').attr('selected', 'selected');
		}

		$('input#_settings_packet_capture').on('click', function () {
			if ($('input#_settings_packet_capture').is(':checked')) {
				$('div.pc-settings').show();
				$('p.pc-settings input[type="text"], p.pc-settings select').addClass('required');
			} else {
				$('div.pc-settings').hide();
				$('p.pc-settings input[type="text"], p.pc-settings select').removeClass('required');
			}
		});

		$('input#_settings_autodrop').on('click', function () {

			if ($(this).is(':checked')) {
				$('select#_settings_autodrop_count').attr('disabled', null);
			} else {
				$('select#_settings_autodrop_count').attr('disabled', 'disabled');
			}

		});

		$('input#_settings_packet_capture_auto_auth').on('click', function () {
			if ($('input#_settings_packet_capture_auto_auth').is(':checked')) {
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').addClass('required');
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').attr('disabled', null);
			} else {
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').removeClass('required');
				$('input#_settings_packet_capture_user, input#_settings_packet_capture_password').attr('disabled', 'disabled');
			}
		});

	},

	jobs: function () {

		$('a.view_job_handler, a.view_job_last_error').limp({
			cache: true,
			round: 0,
			loading: true,
			animation: 'pop',
			enableEscapeButton: true,
			shadow: '0 1px 30px rgba(0,0,0,0.6)',
			style: {
				background: 'rgba(36,36,36,0.9)',
				border: '1px solid rgba(0,0,0,0.9)',
				padding: '5px',
				width: '700px'
			},
			inside: {
				border: '1px solid rgba(0,0,0,0.9)',
				padding: 0
			},
			overlay: {
				background: '#000',
				opacity: 0.6
			},
			onOpen: function () {
				Bricata.eventCloseHotkeys(false);
				$('dl#event-sub-menu').hide();
			},
			afterOpen: function (limp, html) {

				html.find('#bricatabox-content .add_chosen').chosen({
					allow_single_deselect: true
				});
			},
			onClose: function () {
				Bricata.eventCloseHotkeys(true);
			}
		});

	}

};

jQuery(document).ready(function ($) {

	Handlebars.registerHelper('geoip', function (ip) {
		if (ip) {
			var name = ip.country_name;
			var code = ip.country_code2;
			if (name === "--") {
				name = 'N/A'
			}

			return '<div class="click ' +
				'country_flag add_tipsy_html" title="&lt;img class=&quot;flag&quot; ' +
				'src=&quot;/images/flags/' + code.toLowerCase() + '.png&quot;&gt; ' + name + '">' + code + '</div>';
		} else {
			return null;
		}
	});

	Handlebars.registerHelper('format_time', function (time) {
		// 2012-09-22 19:25:13 UTC
		return moment(time).utc().add('seconds', Bricata.current_user.timezone_offset).format('MMMM DD, YYYY HH:mm:ss'); //.fromNow();
	});

	Handlebars.registerHelper('short_format_time', function (time) {
		// 2012-09-22 19:25:13 UTC
		return moment(time).utc().add('seconds', Bricata.current_user.timezone_offset).format('MM/DD/YY HH:mm:ss'); //.fromNow();
	});

	Handlebars.registerHelper('format_unix_js', function (time) {
		// 2012-09-22 19:25:13 UTC
		time = Math.floor(time / 1000);
		return moment.unix(time).utc().add('seconds', Bricata.current_user.timezone_offset).format('MM/DD/YY hh:mm:ss A ') + Bricata.current_user.timezone; //.fromNow();
	});

	Handlebars.registerHelper('truncate', function (data, length) {
		if (data.length > length) {
			return data.substring(0, length) + "...";
		} else {
			return data;
		}
	});

	Handlebars.registerHelper('build_asset_name_agent_list', function () {
		var buffer = "";

		for (var i = 0; i < this.agents.length; i += 1) {
			var a = this.agents[i], name;

			if (a.name === "Click To Change Me") {
				name = a.hostname;
			} else {
				name = a.name;
			}

			if (this.hasOwnProperty('agent_ids')) {
				if ($.isArray(this.agent_ids)) {
					if ($.inArray(a.sid, this.agent_ids) >= 0) {
						buffer += "<option selected value='" + a.sid + "'>" + name + "</option>";
					} else {
						buffer += "<option value='" + a.sid + "'>" + name + "</option>";
					}
				} else {
					buffer += "<option value='" + a.sid + "'>" + name + "</option>";
				}
			} else {
				buffer += "<option value='" + a.sid + "'>" + name + "</option>";
			}

		}

		return buffer;
	});


	Handlebars.registerHelper('sensor_name', function () {
		if (this.name === "Click To Change Me") {
			return this.hostname;
		} else {
			return this.name;
		}
	});


	Handlebars.registerHelper('percentage', function (total) {
		var calc = ((parseFloat(this.events_count) / parseFloat(total)) * 100);
		return calc.toFixed(2);
	});

	$('#user_new').submit(function (event) {
		event.preventDefault();
		var self = $('#login');
		var that = this;

		if ($('#password').length > 0) {
			that.submit();
		} else {
			var password_value = $('input#user_password', that).val();
		}

		var email_value = $('input#user_email', that).val(),
			licenseAgreement = 0;

		if (password_value && (password_value.length > 1)) {
			if (email_value.length > 5) {
				$('div.auth-loading').fadeIn('slow');
				$.post(that.action, $(that).serialize(), function (data) {
					if (data.success) {
						if (data.user && data.user.sign_in_count) {
							licenseAgreement = data.user.license_agreement;
						}
						$('div.auth-loading span').fadeOut('slow', function () {
							$(this).html('Authentication Successful, Please Wait...');
							$(this).fadeIn('slow');
						});
						$.get(data.redirect, function (data) {
							if (licenseAgreement === 0) {
								$('#login').hide();
								$('#license').show();
								$('#agreeLicense').on('click', function () {
									$.ajax({
										method: "POST",
										url: "license",
										data: {
											_method: "put",
											authenticity_token: csrf,
											user: {license_agreement: 1}
										}
									}).done(function () {
										self.fadeOut(500, function () {
											setTimeout(function(){ 
												document.open();
												document.write(data);
												document.close();
												history.pushState(null, 'Bricata - Dashboard', baseuri + '/');
											}, 100);
										});
									});

								});
								$('body').on('click', '#cancelLicense', function () {
									history.pushState(null, '', 'logout');
									history.go();
								});
							}
							else {
								self.fadeOut(500, function () {
									setTimeout(function(){ 
										document.open();
										document.write(data);
										document.close();
										history.pushState(null, 'Bricata - Dashboard', baseuri + '/');
									}, 100);
								});
							}
						});

					} else {
						flash_message.push({
							type: 'error',
							message: "Error, Authentication Failed!"
						});
						flash();
						$('div.auth-loading').fadeOut();
					}
				});
			}
		}
	});

	//remove the title div from login pages
	$('#title').remove();

	$('img.avatar, img.avatar-small, div.note-avatar-holder img').error(function (event) {
		$(this).attr("src", baseuri + "/images/default_avatar.png");
	});

	$('.forgot-my-password').on('click', function (event) {
		event.preventDefault();
		$.get(baseuri + '/users/password/new', function (data) {
			var content = $(data).find('#content').html();
			$('#signin').html(content);
			history.pushState(null, 'Bricata - Password Reset', baseuri + '/users/password/new');
		});
	});

	$('#fancybox-wrap').draggable({
		handle: 'div#box-title',
		cursor: 'move'
	});

	//$('li.administration a').on('click', function(event) {
	//  var self = this;
	//  event.preventDefault();
	//  $('dl#admin-menu').toggle();
	//});

	//$('#admin-menu a').on('click', function(event) {
	//  $(this).parents('dl').fadeOut('fast');
	//});

	$('#wrapper').on('click', function () {
		var selector = $('#admin-menu');
		if (selector.is(':visible')) {
			selector.fadeOut('fast');
		}
	});

	$('body').on('click', 'td.search-by-signature', function (event) {
		event.preventDefault();
		window.location = $(this).attr('data-url');
	});

	Bricata.setup();
	Bricata.admin();
	Bricata.callbacks();
	Bricata.hotkeys();
	Bricata.jobs();
	Bricata.settings();
	Bricata.validations();

	Bricata.helpers.tipsy();
	Bricata.helpers.dropdown();
	Bricata.helpers.input_style();
	Bricata.helpers.persistence_selections();
	Bricata.helpers.pagenation();

	Bricata.pages.classifications();
	Bricata.pages.dashboard();
	Bricata.pages.events();

	$('.add_chosen').chosen({
		allow_single_deselect: true
	});

	$('body').on('hover', 'ul.table div.content li.event', function () {
		$('ul.table div.content li.event').removeClass('currently-over');
		$(this).toggleClass('currently-over');
	}, function () {
		$(this).toggleClass('currently-over');
	});

	var signature_input_search = null;
	var signature_input_search_last = null;
	var signature_input_search_timeout = null;

	$('#signature-search').on('keyup', function () {
		var value = $(this).val().replace(/^\s+|\s+$/g, '');

		if (value.length >= 3) {

			if (value !== signature_input_search_last) {
				if (signature_input_search) {
					signature_input_search.abort()
				}

				signature_input_search_last = value;

				if ($('div.search-loading').length == 0) {
					$('#title').append(Bricata.templates.searchLoading());
				}

				signature_input_search = $.ajax({
					url: baseuri + '/signatures/search',
					global: false,
					data: {q: value, authenticity_token: csrf},
					type: "POST",
					dataType: "json",
					cache: false,
					success: function (data) {
						signature_input_search = null;
						signature_input_search_last = value;

						$('#signatures').hide();
						$('div.search-loading').remove();

						if ($('#signatures-input-search').length == 0) {
							$('#content').append(Bricata.templates.signatureTable());
						}

						$('#signatures-input-search tbody.signatures').html(Bricata.templates.signatures(data));
					}
				});
			}

		} else {
			$('#signatures').show();
			$("#signatures-input-search").remove();
			$('div.search-loading').remove();
			signature_input_search_last = null;
			if (signature_input_search) {
				signature_input_search.abort()
			}
		}
	});

	var cache_reload_count = 0;

	function currently_caching() {
		$.ajax({
			url: baseuri + '/cache/status',
			global: false,
			dataType: 'json',
			cache: false,
			type: 'GET',
			success: function (data) {
				if (data.caching) {
					setTimeout(function () {
						cache_reload_count = 0;
						currently_caching();
					}, 2000);
				} else {
					if (cache_reload_count == 3) {
						cache_reload_count = 0;
						location.reload();
					} else {
						cache_reload_count++;
						currently_caching();
					}
				}
			}
		});
	}

	$('.force-cache-update').on('click', function (e) {
		e.preventDefault();
		$('li.last-cache-time')
			.html("<i>Currently Caching <img src='../images/icons/pager.gif' width='16' height='11' /></i>");

		$.getJSON(this.href, function (data) {
			setTimeout(currently_caching, 6000);
		});
	});

	$('body').on('click', '.bricata-content-restore', function (e) {
		e.preventDefault();

		if ($('.tmp-content-data').length > 0) {

			$('.tmp-content-data, #footer').stop().delay(100).animate({
				opacity: 0
			}, 600, function () {
				$('.tmp-content-data').hide();

				$('.original-content-data, #footer').stop().delay(100).show().animate({
					opacity: 1
				}, 600);
			});
		}

	});

	$('body').on('click', '.bricata-content-replace',function (e) {
		e.preventDefault();

		if ($('.tmp-content-data').length > 0) {

			$('.original-content-data, #footer').stop().delay(100).animate({
				opacity: 0
			}, 600, function () {
				$('.original-content-data').hide();
				$('.tmp-content-data, #footer').stop().delay(100).show().animate({
					opacity: 1
				}, 600);
			});

		} else {

			$('#content').addClass('original-content-data');

			var item = '<li><a href="#" class="bricata-content-restore"><img' +
				' alt="Restart" src="' + baseuri + '/images/icons/restart.png">Go Back</a></li>';
			var menu = '<ul class="" id="title-menu-holder"><ul id="title-menu">' +
				'<li>&nbsp;</li>' + item + '<li>&nbsp;</li></ul></ul>';

			$.ajax({
				url: 'saved/searches',
				global: false,
				dataType: 'html',
				cache: false,
				type: 'GET',
				success: function (data) {

					var $content = $(data).find('#content')
						.addClass('tmp-content-data').hide().css({
							opacity: 0
						});

					var titleMenu = $content.find('#title-menu');

					if (titleMenu.length > 0) {
						titleMenu.find('li:last-child').before(item);
					} else {
						$content.find('#title').append(menu);
					}

					$('.original-content-data, #footer').stop().delay(100).animate({
						opacity: 0
					}, 600, function () {
						var selector = $('.original-content-data');
						selector.before($content);
						selector.hide();
						$('.tmp-content-data, #footer').stop().delay(100).show().animate({
							opacity: 1
						}, 600);
					});
				}
			});
		}
	});

	$('body').on('click', 'button.new-saved-search-record', function (e) {
		e.preventDefault();
		var dd = false;

		if (typeof rule !== "undefined") {
			dd = rule.pack();
		} else {
			var tmpSavedSearch, cookie = document.cookie.split(';');

			$.each(cookie, function(i){
				tmpSavedSearch = cookie[i].match(/^(.*tmpSavedSearch=)/);
				if(tmpSavedSearch) {
					tmpSavedSearch = JSON.parse(cookie[i].match(/\{.*/)[0]);
					return false;
				}
			});

			if (tmpSavedSearch) {
				try {
					dd = {
						match_all: tmpSavedSearch.match_all,
						search: tmpSavedSearch.items
					};
				} catch (e) {
					dd = false;
				}
			}
		}

		if (dd) {
			$('#bricata-box #form-actions button.success').attr('disabled', true);
			$('#bricata-box #form-actions button.success span').text('Please Wait...');

			var title = $('input#saved_search_title').val();
			var search_public = $('input#saved_search_public').is(":checked");

			$.ajax({
				url: baseuri + '/saved_searches/create',
				global: false,
				dataType: 'json',
				cache: false,
				type: 'POST',
				data: {
					"authenticity_token": csrf,
					"search": {
						"title": title,
						"public": search_public,
						"search": dd
					}
				},
				success: function (data) {

					if (data.error) {
						flash_message.push({type: 'error', message: "Error: This search may already exists."});
						flash();
					} else {
						flash_message.push({type: 'success', message: "Your search was saved successfully"});
						flash();
					}

					$(document).trigger('limp.close');

					window.location.href = '/saved/searches';
				},
				error: function (data) {
					flash_message.push({type: 'error', message: "Error: This search may already exists."});
					flash();
					$(document).trigger('limp.close');
				}
			});

		} else {
			flash_message.push({type: 'error', message: "An Unknown Error Has Occurred"});
			flash();
			$(document).trigger('limp.close');
		}
	});

	$('body').on('click', 'div.results a.table-sort-link', function (e) {
		e.preventDefault();

		if ($('#search-params').length > 0) {

			var search_data = JSON.parse($('div#search-params').text());

			var direction = $(this).data('direction');
			var sort = $(this).data('sort');
			var page = $(this).data('page');

			var title = $(this).data('title');
			var search_id = $(this).data('search-id');

			var url = baseuri + "/results?sort=" + sort +
				"&direction=" + direction + "&page=" + page;

			var params = {
				match_all: search_data.match_all,
				search: search_data.search,
				authenticity_token: csrf
			};

			if (title) {
				params.title = title;
			}
			if (search_id) {
				params.search_id = "" + search_id + "";
			}

			if (search_data) {
				post_to_url(url, params);
			}

		}

		return false;
	});

	// Disable clicking on deleting rows
	$('body').on('click', 'tr.deleted *', function (e) {
		$('.edit-sensor-name').unbind('click');
		e.preventDefault();
	});

	$('body').on('change', '#is-asset-name-global', function (e) {
		var value = $(this).is(':checked');
		if (value) {
			$('#edit-asset-name-agent-select').attr('disabled', true);
			$('.add_chosen').trigger("liszt:updated");
		} else {
			$('#edit-asset-name-agent-select').attr('disabled', false);
			$('.add_chosen').trigger("liszt:updated");
		}
	});

	$('body').on('click', '.edit-asset-name', function (e) {
		e.preventDefault();
		var self = $(this);

		if (Bricata.getSensorList) {
			Bricata.getSensorList.abort();
		}

		$('.loading-bar').slideDown('fast');

		Bricata.getSensorList = $.ajax({
			url: baseuri + "/sensors/agent_list.json",
			type: "GET",
			dataType: "json",
			success: function (data) {

				$('.loading-bar').slideUp('fast');

				var params = {
					ip_address: self.attr('data-ip_address'),
					agent_id: self.attr('data-agent_id'),
					asset_name: self.attr('data-asset_name'),
					asset_id: self.attr('data-asset_id'),
					global: (self.attr('data-asset_global') === "true" ? true : false),
					agents: data
				};

				params.agent_ids = [];
				if (self.attr('data-asset_agent_ids')) {
					var ids = self.attr('data-asset_agent_ids').split(',');
					for (var i = 0; i < ids.length; i += 1) {
						params.agent_ids.push(parseInt(ids[i]));
					}
				}
				var box = Bricata.box('edit-asset-name', params);
				box.open();
			},
			error: function (a, b, c) {
				$('.loading-bar').slideUp('fast');
				flash_message.push({
					type: 'error',
					message: "Unable to edit asset name for address."
				});
				flash();
			}
		});

	});

	$('body').on('click', 'a.destroy-asset-name', function (e) {
		e.preventDefault();
		var id = $(this).attr('data-asset_id');

		var box = Bricata.box('confirm', {
			title: "Remove Asset Name",
			message: "Are you sure you want to remove this asset name? This action cannot be undone.",
			button: {
				title: "Yes",
				type: "default success"
			},
			icon: "warning"
		}, {
			onAction: function () {
				$('.loading-bar').slideDown('fast');
				$('.limp-action').attr('disabled', true).find('span').text('Loading...');
				$.ajax({
					url: baseuri + '/asset_names/' + id + '/remove',
					type: 'delete',
					data: {
						csrf: csrf
					},
					dataType: "json",
					success: function (data) {
						$('.loading-bar').slideUp('fast');
						$.limpClose();
						$('tr[data-asset-id="' + id + '"]').remove();
					},
					error: function (a, b, c) {
						$('.loading-bar').slideUp('fast');
						$.limpClose();
					}
				});
			}
		});
		box.open();
	});

	// Redesign scripts
	var loadActiveMenu = function (selector) {
		$(selector)
			.removeClass('active')
			.each(function () {
				var link = $(this).find('a[href]'),
					url = window.location.pathname;
				if (link.attr('href') === '#' &&
					$(link).first().text().trim() === 'Administration' &&
					( url === '/settings' ||
					url === '/classifications' ||
					url === '/lookups' ||
					url === '/asset_names' ||
					url === '/severities' ||
					url === '/users' ||
					url === '/jobs')
				) {
					$(this).addClass('active');
					return false;
				} else if (link.attr('href') === '#' &&
					$(link).first().text().trim() === 'Signatures' &&
					( url === '/static/#/signatures' ||
					url === '/signatures' ||
					url === '/static/#/signatures/categories' ||
					url === '/static/#/signatures/classtypes' ||
					url === '/static/#/signatures/severities' ||
					url === '/static/#/signatures/references')
				) {
					$(this).addClass('active');
					return false;
				}
				else if (link.attr('href') === url) {
					$(this).addClass('active');
					return false;
				}
			});
	};
	var loadSelectedItem = function (selector) {
		$(selector).find('span').text($(selector).find('li.active a').text()).append('<span class="glyphicon glyphicon-triangle-bottom" aria-hidden="true"></span>');
	};

	loadActiveMenu($('#menu').find('li.item, li.administration'));
	loadSelectedItem($('.dashboard-menu'));
	loadSelectedItem($('#box-tabs1'));

	if (navigator.userAgent.indexOf('Firefox/') >=0){
		$('body').addClass('firefox');
	}else if (navigator.userAgent.indexOf('Safari/') >=0){
		$('body').addClass('safari');
	}
});


