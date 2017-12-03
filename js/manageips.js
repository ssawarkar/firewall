var controller = "manageips";

jQuery(document).ready(function ($) {

    var manageIPsDataTable = $('#manageIPsTable').dataTable({
        processing: true,
        serverSide: true,
        ajax: {
            url: url,
            type: "POST",
            data: function (d) {
                d.option = option;
                d.controller = controller;
                d.action = 'getACLIPMap';
                d.task = 'getACLIPMap';
                d.centnounce = $('#centnounce').val();
            }
        },
        columns: [
            {"data": "country_code"},
            {"data": "id"},
            {"data": "datetime"},
            {"data": "name"},
            {"data": "score"},
            {"data": "ip32_start"},
            {"data": "status"},
            {"data": "visits"},
            {"data": "view"},
            {"data": "checkbox", sortable: false}
        ]
    });
    $('#manageIPsTable tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');
    });

    $('#checkedAll').on('click', function () {
        $('#manageIPsTable').dataTable().api().rows()
            .nodes()
            .to$()
            .toggleClass('selected');
    });

    var font = {
        onChange: function (cep, event, currentField, options) {
            if (cep) {
                var ipArray = cep.split(".");
                for (i in ipArray) {
                    if (ipArray[i] != "" && parseInt(ipArray[i]) > 255) {
                        ipArray[i] = '255';
                    }
                }
                var resultingValue = ipArray.join(".");
                $(currentField).val(resultingValue);
            }
        }
    };
    $('#ip_start').mask("099.099.099.099", font);
    $('#ip_end').mask("099.099.099.099", font);
    var statusFilter = $('<label>Status: <select name="statusFilter" id="statusFilter"><option value="0"></option><option value="1">Blacklisted</option><option value="2">Monitored</option><option value="3">Whitelisted</option></select></label>');
    statusFilter.appendTo($("#manageIPsTable_filter")).on('change', function () {
        var val = $('#statusFilter');
        manageIPsDataTable.api().column(7)
            .search(val.val(), false, false)
            .draw();
    });

    $('#manageIPsTable').on('init.dt', function () {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'getKeyName',
                task: 'getKeyName',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                var text = "";
                for (i = 0; i < data.length; i++) {
                    text += '<option value="' + data[i]['keyname'] + '">' + data[i]['keyname'] + '</option>';
                }
                var varFilter = $('<label>Variable: <select name="varFilter" id="varFilter"><option value="0"></option>' + text + '</option></select></label>');
                varFilter.appendTo($("#manageIPsTable_filter")).on('change', function () {
                    var val2 = $('#varFilter');
                    manageIPsDataTable.api().column(9)
                        .search(val2.val(), false, false)
                        .draw();
                });
            }
        })

    });
    $("#add-ip-form").submit(function () {
    	showLoading(O_PLEASE_WAIT);
        var postdata = $("#add-ip-form").serialize();
        postdata += '&centnounce=' + $('#centnounce').val();
        $.ajax({
            type: "POST",
            url: url,
            data: postdata, // serializes the form's elements.
            success: function (data) {
                data = jQuery.parseJSON(data);
                $('#addIPModal').modal('hide');
                if (data.status =='SUCCESS') {
	        		showLoading(data.result);
	            }
	            else {
	        		showDialogue(data.result, data.status, O_OK);
	            }
                hideLoading();
                $('#manageIPsTable').dataTable().api().ajax.reload();
            }
        });
        return false; // avoid to execute the actual submit of the form.
    });
    var correctFormat = O_CSV_FORMAT;
    $('#import-ip-form').submit(function () {
        showLoading();
        $('#centnounceForm').val($('#centnounce').val());
        // submit the form
        $(this).ajaxSubmit({
            url: url,
            success: function (data) {
                data = jQuery.parseJSON(data);
                if (data.success == true) {
                    hideLoading();
                    $('#importModal').modal('hide');
                    $('#manageIPsTable').dataTable().api().ajax.reload();
                    showDialogue(data.result, data.status, O_OK);
                }
                else {
                    hideLoading();
                    showDialogue(data.result + correctFormat, data.status, O_OK);
                }
            }
        });
        // return false to prevent normal browser submit and page navigation 
        return false;
    });

    $('#export-ip-button').click(function () {
        $('#exportModal').modal('hide');
    })
});
function changeView() {
    if (document.getElementById("single_ip").checked == false) {
        document.getElementById("hidden_ip_end").style.display = "block";
    } else {
        document.getElementById("hidden_ip_end").style.display = "none";
    }
}
function changeItemStatus(id, status)
{
	AppChangeItemStatus(id, status, '#manageIPsTable', 'changeIPStatus');
}

function changeBatchItemStatus (action) {
	AppChangeBatchItemStatus (action, '#manageIPsTable');
}

function removeItems () {
    jQuery(document).ready(function ($) {
        ids = $('#manageIPsTable').dataTable().api().rows('.selected').data();
        if (ids.length > 0) {
            AppRemoveItems ('removeips');
        } else {
            showDialogue(O_SELECT_FIRST, O_NOTICE, O_OK);
        }
    })
}

function removeAllItems () {
	AppRemoveAllItems ('removeAllIPs', '#manageIPsTable');
}

function viewIPdetail(id)
{
	showLoading ();
	jQuery(document).ready(function($){
		$.ajax({
	        type: "POST",
	        url: url,
	        dataType: 'json',
		    data: {
		    		option : option, 
		    		controller:controller,
		    		action:'viewAttack',
		    		task:'viewAttack',
		    		id: id,
		    		centnounce:$('#centnounce').val()
		    },
	        success: function(data)
	        {
	        	hideLoading ();
	        	bootbox.dialog({
		    			message: data.result,
		    			title: data.status,
		    			className: 'detailed-form',
		    			buttons: {}
		    	});
	        }
	      });
	});
}

function enableIPV6 (){
    showLoading ("Changing Database structure, please wait...");
    jQuery(document).ready(function($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'enableIPV6',
                task: 'enableIPV6',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                hideLoading ();
                if(data.success == true)
                {
                    showDialogue(data.result,"UPDATE","CLOSE");
                }else{
                    showDialogue(data.result,"ERROR","CLOSE");

                }
            }
        })
    });
}