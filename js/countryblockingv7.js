/**
 * Created by suraj on 21/07/2016.
 */
/**
 * @version     2.0 +
 * @package       Open Source Excellence Security Suite
 * @subpackage    Centrora Security Firewall
 * @subpackage    Open Source Excellence WordPress Firewall
 * @author        Open Source Excellence {@link http://www.opensource-excellence.com}
 * @author        Created on 01-Jun-2013
 * @license GNU/GPL http://www.gnu.org/copyleft/gpl.html
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *  @Copyright Copyright (C) 2008 - 2012- ... Open Source Excellence
 */
var url = ajaxurl;
var controller = "countryblockingv7";
var option = "com_ose_firewall";

jQuery(document).ready(function($){
    colours = $('body').data('appStart').getColors();
    var sizes = $('body').data('appStart').getSizes();
    var countriesDataTable = $('#countryTable').dataTable( {
        processing: true,
        serverSide: true,
        ajax: {
            url: url,
            type: "POST",
            data: function ( d ) {
                d.option = option;
                d.controller = controller;
                d.action = 'getCountryList';
                d.task = 'getCountryList';
                d.centnounce = $('#centnounce').val();
            }
        },
        columns: [
            { "data": "id", width: '5%'},
            { "data": "country_code", width: '5%'},
            { "data": "name"},
            { "data": "status", width: '5%'},
            { "data": "checkbox", sortable: false , width: '5%'}
        ]
    });
    $('#countryTable tbody').on( 'click', 'tr', function () {
        $(this).toggleClass('selected');
    });
    $('#checkedAll').on('click', function() {
        $('#countryTable').dataTable().api().rows()
            .nodes()
            .to$()
            .toggleClass('selected');
    });
    var statusFilter = $('<label>Status: <select name="statusFilter" id="statusFilter"><option value="-1"></option><option value="1">Blacklisted</option><option value="2">Monitored</option><option value="3">Whitelisted</option></select></label>');
    statusFilter.appendTo($("#countryTable_filter")).on( 'change', function () {
        var val = $('#statusFilter');
        countriesDataTable.api().column(3)
            .search( val.val(), false, false )
            .draw();
    });
    plotDownloadPieChart($, sizes.pielinewidth, sizes.piesize, 1500, colours);
    $("#download-geoip-form").submit(function() {
        downLoadFile($, 8);
        return false; // avoid to execute the actual submit of the form.
    });
});

var plotDownloadPieChart = function ($, lineWidth, size, animateTime, colours) {
    $(".easy-pie-chart").easyPieChart({
        barColor: colours.blue,
        borderColor: colours.blue,
        trackColor: colours.gray,
        scaleColor: false,
        lineCap: 'butt',
        lineWidth: lineWidth,
        size: size,
        animate: animateTime
    });
};
function downLoadFile($, step) {
    $('#message-box').waitMe({
        text : 'Please wait...',
    });
    $.ajax({
        type: "POST",
        url: url,
        data: {
            option:option,
            controller:controller,
            action:'downLoadTables',
            task:'downLoadTables',
            step:step,
            centnounce:$('#centnounce').val()
        },
        success: function(data)
        {
            data = jQuery.parseJSON(data);
            $('#message-box').waitMe("hide");
            $('#message-box').html(data.result);
            if (data.status == 'unfinish')
            {
                var pct = Math.round((1 - (step - 1) / 8) * 100);
                $('#easy-pie-chart-1').data('easyPieChart').update(pct);
                $('#easy-pie-chart-1').attr("data-percent", pct);
                $('#pie-1').html(pct + '%');
                downLoadFile($, step-1);
            }
            else
            {
                var pct = 100;
                $('#easy-pie-chart-1').data('easyPieChart').update(pct);
                $('#easy-pie-chart-1').attr("data-percent", pct);
                $('#pie-1').html(pct + '%');
                createTables ($, 0);
            }
        }
    });
}

function createTables($, step) {
    $('#message-box').waitMe({
        effect : 'facebook',
        text : 'Please wait...',
        bg : 'rgba(255,255,255,0.7)'
    });
    $.ajax({
        type: "POST",
        url: url,
        data: {
            option:option,
            controller:controller,
            action:'createTables',
            task:'createTables',
            step:step,
            centnounce:$('#centnounce').val()
        },
        success: function(data)
        {
            data = jQuery.parseJSON(data);
            $('#message-box').waitMe("hide");
            $('#message-box').html(data.result);
            if (data.cont == 1)
            {
                var pct = Math.round((step / 10) * 100);
                $('#easy-pie-chart-1').data('easyPieChart').update(pct);
                $('#easy-pie-chart-1').attr("data-percent", pct);
                $('#pie-1').html(pct + '%');
                createTables($, step+1);
            }
            else
            {
                var pct = 100;
                $('#easy-pie-chart-1').data('easyPieChart').update(pct);
                $('#easy-pie-chart-1').attr("data-percent", pct);
                $('#pie-1').html(pct + '%');
                $('#message-box').html('Completed');
                $('#countryTable').dataTable().api().ajax.reload();
                $('#formModal').modal('hide');
                showDialogue (O_COUNTRYBLOCK_DATABASE_COMPLETED, 'Completed', 'OK');
            }
        }
    });
}

function changeItemStatus(id, status)
{
    AppChangeItemStatus(id, status, '#countryTable', 'changeCountryStatus');
}

function changeBatchItemStatus (action) {
    AppChangeBatchItemStatus (action, '#countryTable');
}

function removeItems () {
    AppRemoveItems ('deleteCountry');
}

function removeAllItems () {
    AppRemoveAllItems ('deleteAllCountry', '#countryTable');
}

function loadData (action) {
    AppRunAction (action, '#countryTable');
}