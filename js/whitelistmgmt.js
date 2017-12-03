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
var controller = "whitelistmgmt";

jQuery(document).ready(function($) {

    var rulesetsDataTable = $('#variablesTable').dataTable( {
        processing: true,
        serverSide: true,
        ajax: {
            url: url,
            type: "POST",
            data:  {
                option : option,
                controller : controller,
                action : 'getEntityList',
                task : 'getEntityList',
                centnounce : $('#centnounce').val(),
            }
        },
        columns: [
            { "data": "id", width: '5%'},
            { "data": "entity", width: '30%'},
            { "data": "entity_type" , width: '25%'},
            { "data": "request_type" , width: '25%'},
            { "data": "status", sortable: false , width: '10%'},
        ]
    });
    $('#variablesTable tbody').on( 'click', 'tr', function () {
        $(this).toggleClass('selected');
    });

    var statusFilter = $('<label>Status: <select name="statusFilter" id="statusFilter">' +
        '<option value="4">'+O_ALL+'</option>' +
        '<option value="2">'+O_SCANNED+'</option>' +
        '<option value="1">'+O_FILTERED+'</option>' +
        '<option value="3">'+O_IGNORED+'</option>' +
        '</select></label>');
    statusFilter.appendTo($("#variablesTable_filter")).on( 'change', function () {
        var val = $('#statusFilter');
        rulesetsDataTable.api().column(4)
            .search( val.val(), false, false )
            .draw();
    });

    var typeFilter = $('<label>'+O_TYPE+': <select name="typeFilter" id="typeFilter">' +
        '<option value="3">'+O_ALL+'</option>' +
        '<option value="2">'+O_STRINGS+'</option>' +
        '<option value="1">'+O_VARIABLES+'</option>' +
        '</select></label>');
    typeFilter.appendTo($("#variablesTable_filter")).on( 'change', function () {
        var val = $('#typeFilter');
        rulesetsDataTable.api().column(2)
            .search( val.val(), false, false )
            .draw();
    });

    $("#add-variable-form").submit(function() {
        showLoading(O_PLEASE_WAIT);
        var postdata = $("#add-variable-form").serialize();
        postdata += '&centnounce=' + $('#centnounce').val();
        $.ajax({
            type: "POST",
            url: url,
            data: postdata, // serializes the form's elements.
            success: function(data)
            {
                data = jQuery.parseJSON(data);
                $('#formModal').modal('hide');
                if (data.status =='SUCCESS') {
                    showLoading(data.result);
                }
                else {
                    showDialogue(data.result, data.status, O_OK);
                }
                $('#variablesTable').dataTable().api().ajax.reload();
                hideLoading();
            }
        });
        return false; // avoid to execute the actual submit of the form.
    });

});

function removeItem (deleteallrecords) { // 1 for delete all the records
    deleteallrecords = (deleteallrecords === undefined) ? 0 : deleteallrecords;
    jQuery(document).ready(function ($) {
        ids= encodeAllIDs($('#variablesTable').dataTable().api().rows('.selected').data());
        if (ids.length > 0) {
            confirmRemoveItems (ids,deleteallrecords);
        } else {
            showDialogue(O_SELECT_FIRST, O_NOTICE, O_OK);
        }
    })
}
function confirmRemoveItems(ids,deleteallrecords)
{
    if(deleteallrecords == 0)
    {
        var message =  O_DELETE_CONFIRM_DESC_FW7_IPMGMT+" <br/>";
    }else {
        var message = O_DELETE_ALL_IP_RECORDS+" <br/>";
    }
    bootbox.dialog({
        message: message,
        title: "Confirmation",
        buttons: {
            success: {
                label: "Yes",
                className: "btn-success",
                callback: function () {
                    if(deleteallrecords == 1)
                    {
                        clearAllRecords();
                    }else {
                        deleteItems(ids);
                    }
                }
            },
            main: {
                label: "Close",
                className: "btn-primary",
                callback: function () {
                    window.close();
                }
            }
        }
    });
}

function deleteItems(ids){
    jQuery(document).ready(function($){
        showLoading (O_PLEASE_WAIT);
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option : option,
                controller:controller,
                action:'deleteItem',
                task:'deleteItem',
                ids:ids,
                centnounce:$('#centnounce').val()
            },
            success: function(data)
            {
                if (data.status == 'SUCCESS') {
                    showLoading(data.result,"UPDATE","CLOSE");
                }
                else {
                    showDialogue(data.result,"ERROR","CLOSE");
                }
                hideLoading ();
                $('#variablesTable').dataTable().api().ajax.reload(null, false);
            }
        });
    });
}

function clearAllRecords(){
    jQuery(document).ready(function($){
        showLoading (O_PLEASE_WAIT);
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option : option,
                controller:controller,
                action:'clearAll',
                task:'clearAll',
                centnounce:$('#centnounce').val()
            },
            success: function(data)
            {
                if (data.status == 'SUCCESS') {
                    showLoading(data.result,"UPDATE","CLOSE");
                }
                else {
                    showDialogue(data.result,"ERROR","CLOSE");
                }
                hideLoading ();
                $('#variablesTable').dataTable().api().ajax.reload(null, false);
            }
        });
    });
}
function changeBatchItemStatus (action) {
    AppChangeBatchItemStatus (action, '#variablesTable');
}



function loadDefaultVariables($type){
    jQuery(document).ready(function($){
        showLoading (O_PLEASE_WAIT);
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option : option,
                controller:controller,
                action:'loadDefaultVariables',
                task:'loadDefaultVariables',
                type:$type,
                centnounce:$('#centnounce').val()
            },
            success: function(data)
            {
                if (data.status == 'SUCCESS') {
                    showDialogue(data.result,"UPDATE","CLOSE");
                }
                else {
                    showDialogue(data.result,"ERROR","CLOSE");
                }
                hideLoading ();
                $('#variablesTable').dataTable().api().ajax.reload(null, false);
            }
        });
    });
}

function confirmVariableImport()
{
    var message = O_IMPORT_VARIABLE_LIST;
        bootbox.dialog({
            message: message,
            title: "Confirmation",
            buttons: {
                success: {
                    label: "Yes",
                    className: "btn-success",
                    callback: function () {
                        importVariables();
                    }
                },
                main: {
                    label: "Close",
                    className: "btn-primary",
                    callback: function () {
                        window.close();
                    }
                }
            }
        });
}
function importVariables()
{
    jQuery(document).ready(function($){
        showLoading (O_PLEASE_WAIT);
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option : option,
                controller:controller,
                action:'importVariables',
                task:'importVariables',
                centnounce:$('#centnounce').val()
            },
            success: function(data)
            {
                if (data.status == 'SUCCESS') {
                    showLoading(data.result,"UPDATE","CLOSE");
                }
                else {
                    showDialogue(data.result,"ERROR","CLOSE");
                }
                hideLoading ();
                $('#variablesTable').dataTable().api().ajax.reload(null, false);
            }
        });
    });
}

jQuery(document).ready(function($){
    requestTypeUIChange();
    $("#entitytype").change(function(){
        requestTypeUIChange();
    });

});

function requestTypeUIChange(){
    jQuery(document).ready(function($){
    if($( "#entitytype" ).val()=="STRING"){
        $('#whiteform-rt').fadeOut();
        $('#whiteform-label3').text(O_STRING_VALUE);
    }else{
        $('#whiteform-rt').fadeIn();
        $('#whiteform-label3').text(O_ENTITY_KEY_NAME);
    }
    });
}

//adds the default variables in the whitelist to avoid any false alerts from the firewall
function defaultWhiteListVariablesv7()
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'defaultWhiteListVariablesV7',
                task: 'defaultWhiteListVariablesV7',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    $('#addwhitelistvars').hide();
                    $('#variablesTable').dataTable().api().ajax.reload(null, false);
                }
                else {
                    showDialogue("There was some problem in adding the default whitelist variables" , "ERROR", "close");
                }
            }
        });
    });
}