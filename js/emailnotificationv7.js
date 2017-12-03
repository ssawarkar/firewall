/**
 * Created by suraj on 18/08/2016.
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
var controller = "Emailnotificationv7";
var option = "com_ose_firewall";
var settings = new Array();


jQuery(document).ready(function($){
    getSettings();

    $('.em-qmark').each(function(){
        $(this).click(function(){
            return false;
        });
    });
    $("#statistic-section").hide();
    $("#stats").click(function(){
        $("#statistic-section").toggle();
    });
});

function getSettings()
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'getSettings',
                task: 'getSettings',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    settings = data.info;
                    initializeUI();

                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
function saveSettings()
{
    showLoading("Updating Email Preferences");
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'saveSettings',
                task: 'saveSettings',
                data:settings,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                hideLoading();
                if(data.status == 'Success')
                {
                    showDialogue(data.message,"UPDATE","close");

                }else {
                    showDialogue(data.message,"ERROR","close");
                }

            }
        })
    });
}

function initializeUI(){

    jQuery(document).ready(function($){
        for(i=0;i<settings.length;i++){
            if(settings[i].value==1){
              var htmlID =  "#"+settings[i].key;
                $(htmlID).addClass('bg-color-lightgreen');
            }
        }

    });

}

function changeStatus(htmID){
    jQuery(document).ready(function($) {
            if ($("#"+htmID).hasClass('bg-color-lightgreen')){
                //fetching the array and set value
                for(i=0;i<7;i++){
                    if(settings[i].key ==htmID){
                        settings[i].value = 0;
                        $("#"+htmID).removeClass('bg-color-lightgreen');
                    }
                }
            }else{
                for(i=0;i<7;i++){
                    if(settings[i].key ==htmID){
                        settings[i].value = 1;
                        $("#"+htmID).addClass('bg-color-lightgreen');
                    }
                }
            }
        ChangeStatisticsStatus();
    });
}

function changeReportCycleStatus(htmID){
    jQuery(document).ready(function($){
        if ($("#"+htmID).hasClass('bg-color-lightgreen')){
            for(i=7;i<11;i++){
                if(settings[i].key ==htmID){
                    settings[i].value = 0;
                    $("#"+htmID).removeClass('bg-color-lightgreen');
                }
            }
        }else{
            for(i=7;i<11;i++){
                if(settings[i].key ==htmID){
                    settings[i].value = 1;
                    $("#"+htmID).addClass('bg-color-lightgreen');
                }  else {
                    settings[i].value = 0;
                    $("#"+settings[i].key).removeClass('bg-color-lightgreen');
                }
            }
        }
        ChangeStatisticsStatus();
    });
}

function ChangeStatisticsStatus(){
    jQuery(document).ready(function($){
        var count = 0;
        var cycle_count = 0;
        for(i=3;i<7;i++){
            if($("#"+settings[i].key).hasClass('bg-color-lightgreen')){
                count++;
            }
        }
        for(i=7;i<9;i++){
            if($("#"+settings[i].key).hasClass('bg-color-lightgreen')){
                cycle_count++;
            }
        }

        if(count>0 && cycle_count >0){
            settings[2].value = 1;
            $('#stats').addClass('bg-color-lightgreen');
        }
        else {
            settings[2].value = 0;
            $('#stats').removeClass('bg-color-lightgreen');
        }
    });

}