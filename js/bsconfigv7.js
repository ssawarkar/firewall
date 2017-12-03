/**
 * Created by yuliu on 6/14/16.
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
var overAllscore = 253;
var bacScore = 0;
var srsScore = 0;
var fuvScore = 0;
var syScore = 0;
var initScore = 0;
var url = ajaxurl;
var controller = "Bsconfigv7";
var option = "com_ose_firewall";
var fwsets = new Array();
var wizsets = new Array();
var fucCheck = 0;
var srsCheck = 0;
var savedNumber = 0;
var wizardPageNumber = 1;
var wizardGoogleStatus = false;
var secLevel = 0;



jQuery(document).ready(function($){
    showLoading ("Checking firewall status");
    loadAdvanceSettingsPage();
    getSettings();
    isFirewallV7Active();
    window.onbeforeunload = function ()
    {

        var score = bacScore+srsScore+fuvScore+syScore;
           if(score !== initScore){
        $('#save-hint').show();

                return false;
//                return 'You have unsaved changes, sure to leave this page?';
            }
    };
    $('#bfp-close').hide();
    $('#fw-bfp').click(function(){
        moveOutAll();
        moveIn('.bfp-info-sections');
    });

    $('#fw-fuc').click(function(){
        moveOutAll();
        moveIn('.fuc-info-sections');
        setSRSBtn();
    });
    $('#fw-srs').click(function(){
        moveOutAll();
        moveIn('.srs-info-sections');
        setFUCBtn();
    });
    $('#btn-srs-close').click(function(){
       moveOut(('.srs-info-sections'));
        moveIn('.fs-info-sections');
        setSRSBtn();
    });
    $('#btn-fuc-close').click(function(){
        moveOut(('.fuc-info-sections'));
        moveIn('.fs-info-sections');
        setFUCBtn();
    });
    $('#bfp-close').click(function(){
        moveOut(('.bfp-info-sections'));
        moveIn('.fs-info-sections');
    });

    $('[data-toggle="popover"]').popover();
    $('#question-vuf').click(function(){
        //$("[data-toggle='popover']").popover('show').focus();
       //return false to prevent the event from window bubbling up
        return false;
    });
    $('#question-svf').click(function(){
        //return false to prevent the event from window bubbling up
        return false;
    });

    $('#question-blocking').click(function(){
        //return false to prevent the event from window bubbling up
        return false;
    });
    $('#question-ful').click(function(){
        //return false to prevent the event from window bubbling up
        return false;
    });

    $('#fw-wizard').click(function(){
        $('#fo-row').hide();
        $('#uv-row').hide();
        isSuite();
        $("[data-toggle='popover']").popover('hide');
        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_WIZARD);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_WIZARD_DESC);
        });
    });

    $('#fw-uploadvali').click(function(){
        $('#wizard-row').hide();
        $('#fo-row').hide();
        $('#uv-row').fadeIn();
        $('#btn-se-config').click();

        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_ADVANCE_SETTING);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_ADVANCE_SETTING_DESC);
        });
        $( "#uv-row .title-bar" ).empty();
        $("#uv-row .title-bar").text(function (_, ctx) {
            return ctx.replace("", VIEW_SETUP_ADVANCED_FEATURES);
        });
 });
    $('#fw-overview').click(function(){
        $('#wizard-row').hide();
        $('#uv-row').hide();
        $('#fo-row').fadeIn();
        $("[data-toggle='popover']").popover('hide');
        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_FIREWALL_OVERVIEW);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_FIREWALL_OVERVIEW_DESC);
        });
    });
    $('#btn-se-config').click(function(){
        $( '#vuf-table' ).hide();
        $('#ful-table').hide();
        $('#seo-sets').fadeIn();
        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_SEO_CONFIGURATION);
        });
        $( "#uv-row .title-bar" ).empty();
        $("#uv-row .title-bar").text(function (_, ctx) {
            return ctx.replace("", O_SEO_CONFIGURATION_SMALL_DESC);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_SEO_CONFIGURATION_DESC);
        });
    });
    $('#upload-ful').click(function(){
        $('#seo-sets').hide();
        $( '#vuf-table' ).hide();
        toggleFileUploadLog();

        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_FILE_UPLOAD_LOGS_TITLE);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_FIREWALL_CONFIGURATION_DESC);
        });
        $( "#uv-row .title-bar" ).empty();
        $("#uv-row .title-bar").text(function (_, ctx) {
            return ctx.replace("", O_FILE_UPLOAD_LOGS_SMALL_DESC);
        });
    });
    $( "#btn-switch-table" ).click(function(){
        $('#seo-sets').hide();
        $('#ful-table').hide();
        $( '#vuf-table' ).fadeIn();
        $( "#c-tag .tag-title" ).empty();
        $("#c-tag .tag-title").text(function (_, ctx) {
            return ctx.replace("", O_FILE_EXTENSION_CONTROL_TITLE);
        });
        $( "#c-tag .tag-content" ).empty();
        $("#c-tag .tag-content").text(function (_, ctx) {
            return ctx.replace("", O_FILE_EXTENSION_CONTROL_DESC);
        });
        $( "#uv-row .title-bar" ).empty();
        $("#uv-row .title-bar").text(function (_, ctx) {
            return ctx.replace("", O_FILE_EXTENSION_CONTROL_SMALL_DESC);
        });
    });


    $("#fc-fs-on").click(function(){
        setFireWallStatusUI('fc-fs-on');
        setArray(1,1);
        showLoading();
        saveSettingsStatus();
    });
    $("#fc-fs-off").click(function(){
        setFireWallStatusUI('fc-fs-off');
        setArray(1,0);
        showLoading();
        saveSettingsStatus();
    });
    $("#fc-mod-block").click(function(){
        $('#fc-mod-filter').removeClass("switch-font-control");
        $('#fc-mod-block').addClass("switch-font-control");
        setArray(17,1);
        //TRIGGER BOX
        $('#mod-block-box').fadeIn();
    });
    $("#mod-block-box-done").click(function(){
        $('#mod-block-box').fadeOut();
    });
    $("#fc-mod-filter").click(function(){
        $('#fc-mod-block').removeClass("switch-font-control");
        $('#fc-mod-filter').addClass("switch-font-control");
        setArray(17,0);
    });
    $("#bfp-on").click(function(){
        $('#bfp-belongings').removeClass("disable");
        $('#bfp-off').removeClass("switch-font-control");
        $('#bfp-on').addClass("switch-font-control");
            setArray(15,1);
            addGreenAndIcon('#fw-bfp');
            bacScore -= 15;
    });
    $("#bfp-off").click(function(){
        $('#bfp-belongings').addClass("disable");
        $('#bfp-on').removeClass("switch-font-control");
        $('#bfp-off').addClass("switch-font-control");
        setArray(15,0);
        removeGreenAndIcon('#fw-bfp');
        bacScore += 15;
    });
    $('#google-code').click(function(){
       if($('#bfp-gv-off').hasClass('switch-font-control')){
           $('#code-box-on').hide();
           $('#code-box-off').fadeIn();
           $('#google-code-box').fadeIn();
       }
        else{
           showLoading ("processing QR code");
           getLoginGoogleQRCode();
       }

    });


    $(document).on('click', function (event) {
        if (!$(event.target).closest('#google-code').length) {
            $('#google-code-box').fadeOut();
        }
    });
    $("#bfp-gv-on").click(function(){
        swal({
                title: '<span class="text-danger">'+O_WAENING_NOT_ABLE_LOGIN_THIS_CODE+'</span><br/>' +
                O_WAENING_NEED_GOOGLE_AUTH,
                    //text: "In the 'Google Authenticator Settings' Please click on the active checkbox and Scan the QR Code.",
                //type:"warning",
                html: true,
                showCancelButton: true,
                confirmButtonColor: "#6bc4b5",
                confirmButtonText: O_CONTINUE,
                closeOnConfirm: true
            },
            function(){
                $('#bfp-gv-off').removeClass("switch-font-control");
                $('#bfp-gv-on').addClass("switch-font-control");
                setArray(27,1);
                syScore = -38;
                saveLoginGAuthSettings();
            });

        //openAdminWordpressPage();
    });

    $("#bfp-gv-off").click(function(){
        $('#bfp-gv-on').removeClass("switch-font-control");
        $('#bfp-gv-off').addClass("switch-font-control");
        setArray(27,0);
        syScore = 0;
    });
    $("#bfp-wiz-gv-on").click(function(){
        $('#bfp-wiz-gv-off').removeClass("switch-font-control");
        $('#bfp-wiz-gv-on').addClass("switch-font-control");
        wizardGoogleStatus = true;
    });
    $("#bfp-wiz-gv-off").click(function(){
        $('#bfp-wiz-gv-on').removeClass("switch-font-control");
        $('#bfp-wiz-gv-off').addClass("switch-font-control");
        wizardGoogleStatus = false;
    });

    $('#fw-submit').click(function(){
        jQuery(document).ready(function($){
            var email = $('#wa-email').val();
            if(isEmail(email)){
                showLoading ("Updating Firewall Settings");
                setArray(7,email);
                setArray(25,$('#bfp-login-attempts').val());
                setArray(26,$('#bfp-login-period').val());
                var attemptsValue = $('#mod-block-attempts').val();
                var numbersValue =$('#mod-block-numbers').val();
                setArray(33,attemptsValue);
                //setArray(34,numbersValue);
                saveSettings();
                setFUCBtn();
                setSRSBtn();
                buildScores();
                matchScore();
                $('#save-hint').hide();
            }
            else {
                alert(O_ENTER_EMAIL_IN_FIREWALL_OVERVIEW_SETTING);
                $('#wa-email').val("");
                $('#wa-email').attr("placeholder", O_FILL_VALIDATE_EMAIL_ADDRESS);
            }
        });
    });


    $("#seo-configuraton-formv7").submit(function() {
        showLoading(O_PLEASE_WAIT);
        var postdata = $("#seo-configuraton-formv7").serialize();
        postdata += '&centnounce=' + $('#centnounce').val();
        $.ajax({
            type: "POST",
            url: url,
            data: postdata, // serializes the form's elements.
            success: function(data) {
                data = jQuery.parseJSON(data);
                //$('#formModal').modal('hide');
                hideLoading();
                if (data.status =='1') {
                    showLoading(data.info);
                }
                else {
                    //alert('inside the statuys = 0 loop');
                    showDialogue(data.info, data.status, O_OK);
                }
                //$('#variablesTable').dataTable().api().ajax.reload();
            }
        });
        return false; // avoid to execute the actual submit of the form.
    });


});

function moveOutAll(){
    jQuery(document).ready(function($){
        moveOut('.fs-info-sections');
        moveOut('.srs-info-sections');
        moveOut('.fuc-info-sections');
        moveOut('.bfp-info-sections');
    });
}

jQuery(document).ready(function ($) {

    $('#btn-srs-sa').click(function(){
        selectAll();
        srsScore = -120;
        srsCheck = 8;
    });
    $('#btn-srs-dsa').click(function(){
        deSelectAll();
        srsScore = 0;
        srsCheck = 0;
    });
    $('#btn-fuc-sa').click(function(){
        setArray(13,1);
        setArray(14,1);
        $('#fw-vuf').addClass("bg-color-midiumgreen");
        $('#fw-svf').addClass("bg-color-midiumgreen");
        setFucTabbleUI('#fw-vuf',false);
        setFucTabbleUI('#fw-svf',false);
        fucCheck = 2;
        fuvScore = -50;
    });
    $('#btn-fuc-dsa').click(function(){
        setArray(13,0);
        setArray(14,0);
        $('#fw-vuf').removeClass("bg-color-midiumgreen");
        $('#fw-svf').removeClass("bg-color-midiumgreen");
        setFucTabbleUI('#fw-vuf',true);
        setFucTabbleUI('#fw-svf',true);
        fucCheck = 0;
        fuvScore = 0;
    });
});

function setFireWallStatusUI(status){
    jQuery(document).ready(function($){
        if(status == 'fc-fs-on'){
            $('#fc-fs-off').removeClass("switch-font-control");
            $('#fc-fs-on').addClass("switch-font-control");
            $('#fo-row').removeClass('turnGrayscale');
            $('#fw-securitytag').css('opacity','1');
        }
        else {
            $('#fc-fs-on').removeClass("switch-font-control");
            $('#fc-fs-off').addClass("switch-font-control");
            $('#fo-row').addClass('turnGrayscale');
            $('#fw-securitytag').css('opacity','0.6');
            $('#fw-submit').addClass('disable');
        }
    });
}

function setFUCBtn(){
    if (fucCheck >0){
        addGreenAndIcon('#fw-fuc');
    }
    else {
        removeGreenAndIcon('#fw-fuc');
    }
}
function setSRSBtn(){
    if (srsCheck >0){
        addGreenAndIcon('#fw-srs');
    }
    else {
        removeGreenAndIcon('#fw-srs');
    }
}
function buildShield(s) {
//    var timeline = new TimelineMax();
//    var to = {
//        y: s,
////    ease: Linear.easeOut
//    };
//    var duration = 2;
//    timeline.to("#fill", duration, to, 1);

    TweenMax.to("#fill-shield", 4, {y:s, ease:Power1.easeInOut});
}

function setAttemptsSlider(number){
    jQuery(document).ready(function($){
        var sliderAttempts = new Slider("#mod-block-attempts");
        sliderAttempts.setValue(number);
        $("#attempts-value").html(number);
        //slide functions
        $("#mod-block-attempts").on("slide", function(slideEvt) {
            var value = slideEvt.value;
            $("#attempts-value").html(value);
        });
    });
}

function setSlider(number){
    jQuery(document).ready(function ($) {
        var slider = new Slider("#fwslider");
        //initial set up
        switch(number) {
            case '90':
                //syScore = 0;
                slider.setValue(0);
                setSensitivityLabelAndArray(0);
                break;
            case '45':
                //syScore = -8;
                slider.setValue(1);
                setSensitivityLabelAndArray(1);
                break;
            case '35':
                //syScore = -18;
                slider.setValue(2);
                setSensitivityLabelAndArray(1);
                break;
            case '25':
                //syScore = -28;
                slider.setValue(3);
                setSensitivityLabelAndArray(3);
                break;
            case '15':
                //syScore = -38;
                slider.setValue(4);
                setSensitivityLabelAndArray(4);
                break;
            default:
                slider.setValue(0);
                setSensitivityLabelAndArray(0);
        }

        //slide function
        $("#fwslider").on("slide", function(slideEvt) {
            var value = slideEvt.value;
            setSensitivityLabelAndArray(value);
        });
    });
}
function setSensitivityLabelAndArray(n){
    jQuery(document).ready(function ($) {
        switch(n) {
            case 0:
                //syScore = 0;
                $("#slide-value").text(O_INSENSITIVE);
                setArray(9,90);
                break;
            case 1:
                //syScore = -8;
                $("#slide-value").text(O_MODERATE);
                setArray(9,45);
                break;
            case 2:
                //syScore = -18;
                $("#slide-value").text(O_SENSITIVE);
                setArray(9,35);
                break;
            case 3:
                //syScore = -28;
                $("#slide-value").text(O_VERY_SENSITIVE);
                setArray(9,25);
                break;
            case 4:
                //syScore = -38;
                $("#slide-value").text(O_HIGHTLY_SENSITIVE);
                setArray(9,15);
                break;
        }
    });
}


function selectAll(){
    addSRSGreen("#fw-csrf",'3');
    addSRSGreen("#fw-css",'2');
    addSRSGreen("#fw-si",'4');
    addSRSGreen("#fw-rfi",'5');
    addSRSGreen("#fw-lfi",'6');
    addSRSGreen("#fw-fsa",'12');
    addSRSGreen("#fw-lfma",'10');
    addSRSGreen("#fw-dt",'8');
}
function deSelectAll(){
    removeSRSGreen("#fw-csrf",'3');
    removeSRSGreen("#fw-css",'2');
    removeSRSGreen("#fw-si",'4');
    removeSRSGreen("#fw-rfi",'5');
    removeSRSGreen("#fw-lfi",'6');
    removeSRSGreen("#fw-fsa",'12');
    removeSRSGreen("#fw-lfma",'10');
    removeSRSGreen("#fw-dt",'8');
}


function removeGreenAndIcon(id){
    jQuery(document).ready(function($){
        var classStr = id + ' .shield-square';
        var iconStr = id + ' i';
        $(id).removeClass("bg-color-lightgreen");
        $(classStr).removeClass("bg-color-midiumgreen");
        $(iconStr).css('opacity','0.04');
    });
}
function addGreenAndIcon(id){
    jQuery(document).ready(function($){
        var classStr = id + ' .shield-square';
        var iconStr = id + ' i';
        $(id).addClass("bg-color-lightgreen");
        $(classStr).addClass("bg-color-midiumgreen");
        $(iconStr).css('opacity','1');
    });
}

function toggleSettings(id,backEndID){

    jQuery(document).ready(function($){

        if($(id).hasClass("bg-color-lightgreen")){
            setArray(backEndID,0);
            removeGreenAndIcon(id);
            bacScore += 15;
        }
        else{
         //   alert(backEndID+' value 1');
            setArray(backEndID,1);
            addGreenAndIcon(id);
            bacScore -= 15;
        }
    });
}
function toggleFUCSettings(id,backEndID){
    jQuery(document).ready(function($){
        if($(id).hasClass("bg-color-midiumgreen")){
            //alert(backEndID+' value 0');
            setArray(backEndID,0);
            $(id).removeClass("bg-color-midiumgreen");
            setFucTabbleUI(id,true);
            fucCheck = fucCheck -1;
            fuvScore +=25
        }
        else {
            //alert(backEndID+' value 1');
            setArray(backEndID,1);
            $(id).addClass("bg-color-midiumgreen");
            setFucTabbleUI(id,false);
            fucCheck ++;
            fuvScore -=25
        }
    });
}

function setFucTabbleUI(id,status){
    jQuery(document).ready(function($){
        if(status == true){
            if(id =='#fw-vuf'){
                if(!($('#fw-svf').hasClass("bg-color-midiumgreen"))){
                   // alert('dect both button disabled,close both table');
                    $('#vuf-table').addClass('disable-pointer turnBlur');
                    $('#ful-table').addClass('disable-pointer turnBlur');
                    $('#adset-tablehints').show();
                }
                else {
                   // alert('close only vuf table');
                    $('#vuf-table').addClass('disable-pointer turnBlur');
                }

            }else {
                if(!($('#fw-vuf').hasClass("bg-color-midiumgreen"))){
                   // alert('detect both buton disabled');
                    $('#ful-table').addClass('disable-pointer turnBlur');
                    $('#adset-tablehints').show();
                }
            }
        }
        else {
            if(id =='#fw-vuf'){
                //alert('enable both table');
                $('#vuf-table').removeClass('disable-pointer turnBlur');
                $('#ful-table').removeClass('disable-pointer turnBlur');
                $('#adset-tablehints').hide();
            }
            else{
                //alert('enable ful table');
                $('#ful-table').removeClass('disable-pointer turnBlur');
                $('#adset-tablehints').hide();
            }
        }
    });
}

function toggleSRSettings(id,backEndID){
    jQuery(document).ready(function($){
        var box = id +' .srs-checks-content';
        if($(box).hasClass("bg-color-midiumgreen")){
            removeSRSGreen(id,backEndID);
           srsScore += 15;
            srsCheck--;
        }
        else{
            addSRSGreen(id,backEndID);
            srsScore -= 15;
            srsCheck++;
        }
    });
}
function addSRSGreen(id,backEndID){
    //alert(backEndID+' value 1');
    setArray(backEndID,1);
    jQuery(document).ready(function($) {
        var box1 = id + ' .srs-checks-content';
        var box2 = id + ' .srs-square';
        var icon = id + ' .srs-square' + ' i';
        $(box1).addClass("bg-color-midiumgreen");
        $(box2).addClass("bg-color-midiumgreen");
        $(icon).css('opacity', '1');
    });
}
function removeSRSGreen(id,backEndID){
    //alert(backEndID+' value 0');
    setArray(backEndID,0);
    jQuery(document).ready(function($) {
        var box1 = id + ' .srs-checks-content';
        var box2 = id + ' .srs-square';
        var icon = id + ' .srs-square' + ' i';
        $(box1).removeClass("bg-color-midiumgreen");
        $(box2).removeClass("bg-color-midiumgreen");
        $(icon).css('opacity', '0.1');
    });
}
function countNumber(n){
    var n = 253 - n;
    var n = (n/253).toFixed(2);
    var n = n * 100

    jQuery(document).ready(function($){
        $('#fw-levelcount').prop('Counter',savedNumber).animate({
            Counter: n
        }, {
            duration: 4000,
            easing: 'swing',
            step: function (now) {
                $('#fw-levelcount').text(Math.ceil(now));
                secLevel = Math.ceil(now);
            }
        });
        savedNumber = n;
    });

}
function moveIn(class_name){

    jQuery(document).ready(function($){
        if(class_name == ".bfp-info-sections"){
            $('#fw-bfp-section').css('z-index',1);
        }else {
            $('#fw-bfp-section').css('z-index',-1);
        }

        setTimeout(function(){ $(class_name).show(); }, 1500);
        var delay = 0;
        $(class_name).each(function() {
            $(this).delay(delay).css('z-index', 1).animate({
                opacity: 1,
                marginLeft: "-10%",
            }, 300, function() {
            });
            delay += 60;
        });
        delay +=500;
    moveInBtns(class_name,delay-700);
    });
}

function moveOut(class_name){
    jQuery(document).ready(function($){
        var delay = 0;
        $(class_name).each(function() {
            $(this).delay(delay).css('z-index', -1).animate({
                opacity: 0.7,
                marginLeft: "100%",
            }, 300, function() {
            });
            delay += 60;
        });
        delay +=500;
        //hide buttons
        moveOutBtns(class_name,delay-700);

    });
}
function moveOutBtns(class_name,delay){
    jQuery(document).ready(function($){
        class_name = class_name +'-btn';
        $(class_name).css('z-index', -1).fadeOut(700);
    });
}
function moveInBtns(class_name,delay){
    jQuery(document).ready(function($){
        class_name = class_name +'-btn';
        $(class_name).css('z-index', 1).fadeIn(1000);
    });
}


function setArray(key, value)
{
    fwsets[key] = value;
}
function setWizardArray(key, value)
{
    wizsets[key] = value;
}

function buildScores(){
    //syScore = -38;
    //alert("bac score is:"+bacScore+"fuv score is:"+fuvScore+" srs score is:"+srsScore + " google authentication score is:" +syScore );
    countNumber(bacScore+srsScore+fuvScore+syScore+overAllscore);
    buildShield(bacScore+srsScore+fuvScore+syScore+overAllscore);
}

function saveSettings() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'saveSettings',
                task: 'saveSettings',
                settings: fwsets,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    hideLoading();
                    resetUpdatePatternsStyle($);
                    getFirewallSignatureVersionFromFile();
                }else {
                    enableManualUpdate_fw7($);
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}


function resetUpdatePatternsStyle($)
{
    $('#icon-refresh').removeClass('fa fa-exclamation-circle').addClass('fa fa-refresh');
    $('#icon-refresh').removeClass('spinAnimation');
    $('#icon-refresh').removeAttr("onclick");
    $("#vs-div-update").hide();
    $("#vs-div-uptodate").show();
}

function saveSettingsStatus() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'saveSettings',
                task: 'saveSettings',
                settings: fwsets,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                hideLoading();
                if(data.status == 1)
                {
                    location.reload();
                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}

function getSettings() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'getFirewallSettings',
                task: 'getFirewallSettings',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 1) {
                    initializeUI(data.info);
                } else {
                    showDialogue(data.info, "ERROR", "close");
                }

            }
        })
    });
}

function isSuite() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'isSuite',
                task: 'isSuite',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 0) {
                    //is suite
                    $('#wizard-row').fadeIn();
                } else {
                    $('#wizard-row').fadeIn();
                    setWizardArray(15,0);
                    wizardPageNumber = 3;
                    $('#wiz-bfp').hide();
                    $('#wiz-as').fadeIn();
                    $('#li-bfp').removeClass('opacity-100');
                    $('#li-as').addClass('opacity-100');
                    $('#wiz-step').html('Step 3/8');
                    //is not a suite
                    //showDialogue(data.info, "ERROR", "close");
                }

            }
        })
    });
}


function initializeUI(array){
    jQuery(document).ready(function($){
        //mirror server data to local array;
        for(i=1;i<34;i++){
            setArray(i,array[i]);
            setWizardArray(i,array[i]);
        }

        // optimize 4 sets on right
        //check if it is on off model
        if(fwsets[1]==1){
            setFireWallStatusUI('fc-fs-on');
        }
        else{
            setFireWallStatusUI('off');
            $('#fw-levelcount').html('0');
            $('#fw-panel').addClass("no-pointer-event");
            $('#fw-off-mode-hint').show();
            return
        }
        $('#wa-email').val(fwsets[7]);
        setSlider(fwsets[9]);
        setAttemptsSlider(parseInt(fwsets[33]));
        //setNumberSlider(parseInt(fwsets[34]));
        if(fwsets[17] == 1){
            $('#fc-mod-filter').removeClass("switch-font-control");
            $('#fc-mod-block').addClass("switch-font-control");
        }else {
            $('#fc-mod-block').removeClass("switch-font-control");
            $('#fc-mod-filter').addClass("switch-font-control");
        }

        // brute foce sections
        $('#bfp-login-attempts').val(fwsets[25]);
        $('#bfp-login-period').val(fwsets[26]);
        if(fwsets[27]==1){
            syScore = -38;
            $('#bfp-gv-off').removeClass("switch-font-control");
            $('#bfp-gv-on').addClass("switch-font-control");
        } else {
            $('#bfp-gv-on').removeClass("switch-font-control");
            $('#bfp-gv-off').addClass("switch-font-control");
        }
        //optimize first 3 sets
        if(fwsets[15]==1){
            addGreenAndIcon('#fw-bfp');
            $('#bfp-on').addClass("switch-font-control");
            bacScore-=15;
        }else {
            $('#bfp-belongings').addClass("disable");
            $('#bfp-off').addClass("switch-font-control");
        }
        if(fwsets[11]==1){
            addGreenAndIcon('#fw-as');
            bacScore-=15;
        }
        if(fwsets[16]==1){
            addGreenAndIcon('#fw-cua');
            bacScore-=15;
        }



        //optimize 2 sets for 'file upload control'
        if(fwsets[13]==1){
            $('#fw-vuf').addClass("bg-color-midiumgreen");
            addGreenAndIcon('#fw-fuc');
            fucCheck++;
            setFucTabbleUI('#fw-vuf',false);
            fuvScore -=25;
        } else{
            setFucTabbleUI('#fw-vuf',true);
        }
        if(fwsets[14]==1){
            $('#fw-svf').addClass("bg-color-midiumgreen");
            addGreenAndIcon('#fw-fuc');
            fucCheck++;
            setFucTabbleUI('#fw-svf',false);
            fuvScore -=25;
        }
        //optimize 8 sets for scan 'request settings'
        var frontArray = new Array('#fw-css','#fw-csrf','#fw-si','#fw-rfi','#fw-lfi','#fw-dt','#fw-lfma');
        var count = 0;
        for(i=2;i<11;i++){
            //check 2-10,  7(webemail value) and 9(sensitivity slider)  never return 1 so this loop should be good
            if(fwsets[i]==1){
                if(count==6){
                    var divID = frontArray[i-3];
                }
               else if(count==8){
                    var divID = frontArray[i-4];
                }
                else {
                    var divID = frontArray[i-2];
                }
                addSRSGreen(divID,i);
                addGreenAndIcon('#fw-srs');
                srsCheck++;
                srsScore -=15;
            }
            count++;
        }
        if(fwsets[12]==1){
            addSRSGreen("#fw-fsa",'12');
            addGreenAndIcon('#fw-srs');
            srsCheck++;
            srsScore -=15;
        }
        buildScores();
    });
    hideLoading();
    matchScore();

}

function matchScore(){
    //syScore = -38;
    initScore = bacScore+srsScore+fuvScore+syScore;
}

function isEmail(email) {
    var regex = /^([a-zA-Z0-9_.+-])+\@(([a-zA-Z0-9-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}



  //****************************************   Here below are all copied from upload.js and used for 'validate upload files' table ********************

var url = ajaxurl;
var controller = "upload";
var option = "com_ose_firewall";

jQuery(document).ready(function ($) {
    var fileextDataTable = $('#extensionListTable').dataTable({
        processing: true,
        serverSide: true,
        ajax: {
            url: url,
            type: "POST",
            data: function (d) {
                d.option = option;
                d.controller = controller;
                d.action = 'getExtLists';
                d.task = 'getExtLists';
                d.centnounce = $('#centnounce').val();
            }
        },
        columns: [
            {"data": "ext_id"},
            {"data": "ext_name"},
            {"data": "ext_type"},
            {"data": "ext_status"}
        ]
    });

    $('#extensionListTable tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');
    });
    var statusFilter = $('<label>Status: <select name="statusFilter" id="statusFilter"><option value="0"></option><option value="1">Allowed</option><option value="2">Forbidden</option></select></label>');
    statusFilter.appendTo($("#extensionListTable_filter")).on('change', function () {
        var val = $('#statusFilter');
        fileextDataTable.api().column(3)
            .search(val.val(), false, false)
            .draw();
    });
    var typeFilter = $('<label>Type: <select name="typeFilter" id="typeFilter"><option value="0"></option><option value="Text Files">Text Files</option><option value="Data Files">Data Files</option><option value="Audio Files">Audio Files</option><option value="Video Files">Video Files</option>' +
        '<option value="3D Image Files">3D Image Files</option><option value="Raster Image Files">Raster Image Files</option><option value="Vector Image Files">Vector Image Files</option><option value="Page Layout Files">Page Layout Files</option><option value="Spreadsheet Files">Spreadsheet Files</option>' +
        '<option value="Database Files">Database Files</option><option value="Executable Files">Executable Files</option><option value="Game Files">Game Files</option><option value="CAD Files">CAD Files</option><option value="GIS Files">GIS Files</option><option value="Web Files">Web Files</option>' +
        '<option value="Plugin Files">Plugin Files</option><option value="Font Files">Font Files</option><option value="System Files">System Files</option><option value="Settings Files">Settings Files</option><option value="Encoded Files">Encoded Files</option><option value="Compressed Files">Compressed Files</option>' +
        '<option value="Disk Image Files">Disk Image Files</option><option value="Developer Files">Developer Files</option><option value="Backup Files">Backup Files</option><option value="Misc Files">Misc Files</option></select></label>');
    typeFilter.appendTo($("#extensionListTable_filter")).on('change', function () {
        var val = $('#typeFilter');
        fileextDataTable.api().column(2)
            .search(val.val(), false, false)
            .draw();
    });
});
function addExt() {
    jQuery(document).ready(function ($) {
        $('#addExtModal').modal();
    })
}
function changeStatus(status, id) {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'changeStatus',
                task: 'changeStatus',
                status: status,
                id: id,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {

                if (status == 0) {
                    document.getElementById(id).onclick = function () {
                        changeStatus(1, id);
                    };
                    document.getElementById(id).innerHTML = '<div class="fa fa-times color-red">';
                } else {
                    document.getElementById(id).onclick = function () {
                        changeStatus(0, id);
                    };
                    document.getElementById(id).innerHTML = '<div class="fa fa-check color-green">';
                }
            }
        })
    });
}

//******************** Upload log datatable **********************


jQuery(document).ready(function ($) {
    var extLogDataTable = $('#uploadLogTableV7').dataTable({
        processing: true,
        serverSide: true,
        ajax: {
            url: url,
            type: "POST",
            data: function (d) {
                d.option = option;
                d.controller = controller;
                d.action = 'getLogv7';
                d.task = 'getLogv7';
                d.centnounce = $('#centnounce').val();
            }
        },
        columns: [
            {"data": "id" , width: '5%'},
            {"data": "ip" ,width: '20%'},
            {"data": "filename",width: '15%'},
            {"data": "filetype",width: '10%'},
            {"data": "validationstatus",width: '30%'},
            //{"data": "vs_scan_status"},
            {"data": "datetime",width: '20%'},
        ]
    });
    $('#uploadLogTable tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');
    });
    var adstatusFilter = $('<label>Status: ' +
        '<select name="adstatusFilter" id="adstatusFilter">' +
        '<option value="-1"></option>' +
        '<option value="1">Active</option>' +
        '<option value="0">InActive</option>' +
        '</select></label>');
    adstatusFilter.appendTo($("#AdvrulesetsTable_filter")).on('change', function () {
        var val = $('#adstatusFilter');
        adrulesetsDataTable.api().column(4)
            .search(val.val(), false, false)
            .draw();
    });
});

//******************** Wizards ****************************************** Wizards ****************************************** Wizards **********************

jQuery(document).ready(function($) {
  $('#gv-desc').click(function(){
      $('#wiz-gaimage-1').fadeIn();
  });
    $('#wiz-gaimage-1').click(function(){
        $(this).fadeOut();
        $('#wiz-gaimage-2').fadeIn();
    });
    $('#wiz-gaimage-2').click(function(){
        $(this).fadeOut();
        $('#wiz-gaimage-3').fadeIn();
    });
    $('#wiz-gaimage-3').click(function(){
        $(this).fadeOut();
    });

    $('#wiz-skip').click(function () {
        flipPageForward(false);
    });
    $('#wiz-enable').click(function () {
        flipPageForward(true);
    });
    $('#wiz-disable').click(function () {
        flipPageForward(false);
    });
    $('#wiz-back').click(function () {
        flipPageBackward();
    });
    $('#wiz-complete').click(function(){
        setWizardArray(1, 1);
        confirmSaveWizardSettings();
    });

    $('#wiz-go-advance').click(function(){
        setWizardArray(1, 1);
        saveWizardSettings();
        $('#wiz-basic').hide();
        $('#wiz-advance').fadeIn();
    });

    //here are advance clicks
    $('#wiz-ad1-skip').click(function(){
        $('#wiz-ad-1').hide();
        $('#wiz-ad-2').fadeIn();
        $('#ad1-title').removeClass("opacity-100");
        $('#ad2-title').addClass("opacity-100");
    });
    $('#wiz-ad1-imp').click(function(){
        advanceSettingImportWhiteList();
    });
    $('#wiz-ad1-def').click(function(){
        advanceSettingDefultWhiteList();
    });

    $('#wiz-ad2-skip').click(function(){
        $('#wiz-ad-2').hide();
        $('#wiz-ad-3').fadeIn();
        $('#ad2-title').removeClass("opacity-100");
        $('#ad3-title').addClass("opacity-100");
    });
    $('#wiz-ad2-enable').click(function(){
        advanceSettingEableSearchEngine();
    });
    $('#wiz-ad3-fin').click(function(){
        location.reload();
    });

});


function flipPageForward(status){
    jQuery(document).ready(function($){
        switch(wizardPageNumber) {
            case 1:
                //save data
                if(status==true){
                    setWizardArray(15,1);
                    wizardPageNumber = 2;
                    $('#wiz-bfp').hide();
                    $('#wiz-bfp-set').fadeIn();
                    $('#li-bfp').removeClass('opacity-100');
                    $('#li-bfp-set').addClass('opacity-100');
                    $('#wiz-step').html('Step 2/8');

                }else {
                    setWizardArray(15,0);
                    wizardPageNumber = 3;
                    $('#wiz-bfp').hide();
                    $('#wiz-as').fadeIn();
                    $('#li-bfp').removeClass('opacity-100');
                    $('#li-as').addClass('opacity-100');
                    $('#wiz-step').html('Step 3/8');
                }

                break;
            case 2:
                $('#wiz-bfp-set').hide();
                $('#wiz-as').fadeIn();
                $('#li-bfp-set').removeClass('opacity-100');
                $('#li-as').addClass('opacity-100');
                $('#wiz-step').html('Step 3/8');
                wizardPageNumber = 3;
                //save data
                if(status==true){
                    setWizardArray(25,$('#bfp-wiz-attempts').val());
                    setWizardArray(26,$('#bfp-wiz-period').val());
                }

                break;
            case 3:
                $('#wiz-as').hide();
                $('#wiz-fup').fadeIn();
                $('#li-as').removeClass('opacity-100');
                $('#li-fup').addClass('opacity-100');
                $('#wiz-step').html('Step 4/8');
                wizardPageNumber = 4;
                if(status ==true){
                    setWizardArray(11,1);

                }else {
                    setWizardArray(11,0);
                }
                break;
            case 4:
                $('#wiz-fup').hide();
                $('#wiz-rs').fadeIn();
                $('#li-fup').removeClass('opacity-100');
                $('#li-rs').addClass('opacity-100');
                $('#wiz-step').html('Step 5/8');
                wizardPageNumber = 5;

                //save data
                if(status==true){
                    setWizardArray(13,1);
                    setWizardArray(14,1);
                    setWizardArray(16,1);
                }
                else {
                    setWizardArray(13,0);
                    setWizardArray(14,0);

                }


                break;
            case 5:
                $('#wiz-rs').hide();
                $('#wiz-email').fadeIn();
                $('#li-rs').removeClass('opacity-100');
                $('#li-email').addClass('opacity-100');
                $('#wiz-step').html('Step 6/8');
                wizardPageNumber = 6;
                //save data
                for(i=2;i<13;i++){
                    if(i!=7 && i!=9 && i!=11){
                        if(status==true) {
                            setWizardArray(i, 1);
                        }else {
                            setWizardArray(i, 0);
                        }
                    }
                }
                break;
            case 6:
                //save data
                if(status==true){
                    var email = $('#wiz-email-address').val();
                    if(isEmail(email)){
                        setWizardArray(7,email);
                        wizardPageNumber = 7;
                        $('#wiz-email').hide();
                        $('#wiz-block').fadeIn();
                        $('#li-email').removeClass('opacity-100');
                        $('#li-block').addClass('opacity-100');
                        //save the sensitivity settings
                            var radioValue = $("input[name='sensitivity']:checked").val();
                        setWizardArray(9,radioValue);
                    }else {
                        $('#wiz-email-address').val("");
                        $('#wiz-email-address').attr("placeholder", O_FILL_VALIDATE_EMAIL_ADDRESS);
                        return;
                    }
                }else{
                    wizardPageNumber = 7;
                    $('#wiz-email').hide();
                    $('#wiz-block').fadeIn();
                    $('#li-email').removeClass('opacity-100');
                    $('#li-block').addClass('opacity-100');
                }

                $('#wiz-step').html('Step 7/8');

                break;
            case 7:
                $('#wiz-btns').hide();
                $('#wiz-block').hide();
                $('#wiz-com').fadeIn();
                $('#li-block').removeClass('opacity-100');
                $('#li-complete').css('color','#5c544d');
                $('#li-complete').addClass('opacity-100');
                //save data
                if(status==true){
                    setWizardArray(17,1);
                }
                else{
                    setWizardArray(17,0);
                }
                $('#wiz-step').html('Step 8/8');
                break;

        }

    });
}

function flipPageBackward(){
    jQuery(document).ready(function($){
        switch(wizardPageNumber) {
            case 7:
                $('#wiz-block').hide();
                $('#wiz-email').fadeIn();
                $('#li-block').removeClass('opacity-100');
                $('#li-email').addClass('opacity-100');
                $('#wiz-step').html('Step 6/8');
                wizardPageNumber = 6;
                break;

            case 6:
                $('#wiz-email').hide();
                $('#wiz-rs').fadeIn();
                $('#li-email').removeClass('opacity-100');
                $('#li-rs').addClass('opacity-100');
                $('#wiz-step').html('Step 5/8');
                wizardPageNumber = 5;
                break;
            case 5:
                $('#wiz-rs').hide();
                $('#wiz-fup').fadeIn();
                $('#li-rs').removeClass('opacity-100');
                $('#li-fup').addClass('opacity-100');
                $('#wiz-step').html('Step 4/8');
                wizardPageNumber = 4;
                break;
            case 4:
                $('#wiz-fup').hide();
                $('#wiz-as').fadeIn();
                $('#li-fup').removeClass('opacity-100');
                $('#li-as').addClass('opacity-100');
                $('#wiz-step').html('Step 3/8');
                wizardPageNumber = 3;
                break;
            case 3:
                $('#wiz-as').hide();
                $('#wiz-bfp-set').fadeIn();
                $('#li-as').removeClass('opacity-100');
                $('#li-bfp-set').addClass('opacity-100');
                $('#wiz-step').html('Step 2/8');
                wizardPageNumber = 2;
                break;
            case 2:
                $('#wiz-bfp-set').hide();
                $('#wiz-bfp').fadeIn();
                $('#li-bfp-set').removeClass('opacity-100');
                $('#li-bfp').addClass('opacity-100');
                $('#wiz-step').html('Step 1/8');
                wizardPageNumber = 1;
                break;
        }
    });
}
function getGoogleQR() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'getLoginQRCode',
                task: 'getLoginQRCode',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    alert(data.qrcode);
                }else {
                    alert('failed');
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
function confirmSaveWizardSettings()
{

    swal({
            title: "CONFIRMATION",
            text: O_SAVE_WIZARD_CONFIRMATION,
            showCancelButton: true,
            confirmButtonColor: "#6bc4b5",
            confirmButtonText: O_FINISH,
            closeOnConfirm: true
        },
        function(){
            saveWizardSettings();
            location.reload();
        });

}

function saveWizardSettings() {

    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'saveSettings',
                task: 'saveSettings',
                settings: wizsets,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    resetUpdatePatternsStyle($);
                    getFirewallSignatureVersionFromFile();
                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}

function advanceSettingImportWhiteList() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'whitelistmgmt',
                action: 'importVariables',
                task: 'importVariables',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 'SUCCESS')
                {
                    $('#wiz-ad-1').hide();
                    $('#wiz-ad-2').fadeIn();
                    $('#ad1-title').removeClass("opacity-100");
                    $('#ad2-title').addClass("opacity-100");
                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
function advanceSettingDefultWhiteList() {
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'whitelistmgmt',
                action: 'loadDefaultVariables',
                task: 'loadDefaultVariables',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 'SUCCESS')
                {
                    $('#wiz-ad-1').hide();
                    $('#wiz-ad-2').fadeIn();
                    $('#ad1-title').removeClass("opacity-100");
                    $('#ad2-title').addClass("opacity-100");
                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
function advanceSettingEableSearchEngine() {
    var seosettings =  {22: 1, 23: 1, 24: 1};  //replace it with the data values
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'bsconfigv7',
                action: 'saveConfigSEO',
                task: 'saveConfigSEO',
                type :'seo_wizard',
                data : seosettings,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    $('#wiz-ad-2').hide();
                    $('#wiz-ad-3').fadeIn();
                    $('#ad2-title').removeClass("opacity-100");
                    $('#ad3-title').addClass("opacity-100");
                }else {
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
function getLoginGoogleQRCode (){
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'bsconfigv7',
                action: 'getLoginQRCode',
                task: 'getLoginQRCode',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1) {
                    //alert('yes');
                    hideLoading();
                    $('#code-box-off').hide();
                    $('#code-box-on').html(data.qrcode+O_SCAN_QR);
                    $('#code-box-on').fadeIn();
                    $('#google-code-box').fadeIn();

                }else{
                    hideLoading();
                    showDialogue(data.info,"ERROR","close");
                }
            }
        })
    });
}

function saveLoginGAuthSettings (){
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'bsconfigv7',
                action: 'toggleLoginGoogleAuthentication',
                task: 'toggleLoginGoogleAuthentication',
                loginGAuth:'1',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1) {
                    //if (confirm(data.message)) {
                    //    var win = window.open(data.url, '_blank');
                swal({
                        title:data.message,
                        //text: "In the 'Google Authenticator Settings' Please click on the active checkbox and Scan the QR Code.",
                        //type:"warning",
                        html:true,
                        showCancelButton: true,
                        confirmButtonColor: "#6bc4b5",
                        confirmButtonText: O_CONTINUE_TO_USER_PROFILE,
                        closeOnConfirm: true
                    },
                    function(){
                        var win = window.open(data.url, '_blank');
                    });


                    }
                else{
                    showDialogue(data.info,"ERROR","close");
                    $('#bfp-gv-off').addClass("switch-font-control");
                    $('#bfp-gv-on').removeClass("switch-font-control");
                }
            }
        })
    });
}

function toggleFileUploadLog()
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: "advancerulesets",
                action: 'checkUserType',
                task: 'checkUserType',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 0) {
                    $('#ful-table').fadeIn();
                    $('#ful-table').addClass('disable-pointer turnBlur');
                }else{
                    $('#ful-table').fadeIn();
                }
            }
        });
    });
}


//CODE TO UPDATE THE FIREWALL RULES
function checkUserType_fw7()
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: "advancerulesets",
                action: 'checkUserType',
                task: 'checkUserType',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 1) {
                    checkPatternVersion_fw7();
                } else {
                    $( "#icon-refresh" ).one( "click", function() {
                        checkPatternVersion_fw7();
                    });
                    $('#v-sig').text('Click To Update Firewall Patterns');
                    $('#vs-div-uptodate').hide();
                }
            }
        });
    });
}

function checkPatternVersion_fw7()
{
    jQuery(document).ready(function ($) {
        $('#icon-refresh').removeClass('fa fa-exclamation-circle').addClass('fa fa-refresh');
        $('#icon-refresh').addClass('spinAnimation');
        $("#vs-div-uptodate").hide();
        $('#v-sig').text('Checking Firewall Patterns version');
        $('#icon-refresh').prop('onclick',null).off('click');
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: "advancerulesets",
                action: 'checkPatternVersion',
                task: 'checkPatternVersion',
                type : 'ath',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 2) {
                    //show icon and allow user to update the firewall rules
                    enableManualUpdate_fw7($);
                    showDialogue(data.info,'ERROR','CLOSE');
                } else if(data.status == 0){
                    downloadRequest_fw7('ath');
                }else if(data.status==1)
                {
                    $('#icon-refresh').removeClass('spinAnimation');
                    $('#icon-refresh').removeAttr("onclick");
                    $("#vs-div-update").hide();
                    $("#vs-div-uptodate").show();
                    getFirewallSignatureVersionFromFile();  //TODO GET FIREWALL SIGNATURE FROM THE LOCAL FILE
                }
            }
        });
    });
}


function loadAdvanceSettingsPage()
{
    jQuery(document).ready(function($){
        if(window.location.href.indexOf("advsettings") > -1) {
            $('#fw-uploadvali').click();
        }
    });
}

function enableManualUpdate_fw7($) {
    hideLoading();
    $('#icon-refresh').removeClass('spinAnimation');
    $("#vs-div-update").show();
    $("#vs-div-uptodate").hide();
    $('#v-sig').text('Click To Update Firewall Patterns');
    $( "#icon-refresh" ).one( "click", function() {
        downloadRequest_fw7('ath');
        $('#icon-refresh').addClass('spinAnimation');

    });
}

function downloadRequest_fw7(type) {
    jQuery(document).ready(function ($) {
        $('#icon-refresh').addClass('spinAnimation');
        $('#v-sig').text('Downloading Latest Firewall Patterns ');
        $('#icon-refresh').prop('onclick',null).off('click');
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: "advancerulesets",
                action: 'downloadRequest',
                task: 'downloadRequest',
                type: type,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 0) {
                    enableManualUpdate_fw7($);
                    showDialogue(data.info,'ERROR','CLOSE');
                } else {
                    installPatterns_fw7(type);
                }
            }
        });
    });
}



function installPatterns_fw7(type)
{
    jQuery(document).ready(function ($) {
        $('#icon-refresh').addClass('spinAnimation');
        $('#v-sig').text('Installing Latest Firewall Patterns ');
        $('#icon-refresh').prop('onclick',null).off('click');
        $.ajax({
            type: "POST",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: "advancerulesets",
                action: 'installPatterns',
                task: 'installPatterns',
                type: type,
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 0) {
                    enableManualUpdate_fw7($);
                    showDialogue(data.info,'ERROR','CLOSE');
                } else {
                    $('#icon-refresh').removeClass('spinAnimation');
                    $('#icon-refresh').removeAttr("onclick");
                    $("#vs-div-update").hide();
                    $("#vs-div-uptodate").show();
                    getFirewallSignatureVersionFromFile();  //TODO GET FIREWALL SIGNATURE FROM THE LOCAL FILE
                }
            }
        });
    });
}


function getFirewallSignatureVersionFromFile(){
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'advancerulesets',
                action: 'getDatefromVirusCheckFile',
                task: 'getDatefromVirusCheckFile',
                type : 'ath',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data.status == 1) {
                    $('#vs-uptodate').text(data.info);
                    //alert(data.year+ "/" +data.month+ "/"+data.date+ "  "+data.hour+ ":"+data.min+ ":"+data.sec);
                }
            }
        });
    });
}

function isFirewallV7Active(){
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: 'Bsconfigv7',
                action: 'isV7Activated',
                task: 'isV7Activated',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if (data == true) {
                   checkUserType_fw7();
                }else{
                    $('#v-sig').text('Cannot Update at Security Level: '+secLevel+"%");
                    $('#vs-div-uptodate').hide();
                    $('#icon-refresh').removeClass('fa fa-refresh').addClass('fa fa-exclamation-circle');
                    $('#vs-div-update').attr('disabled','disabled');

                }
            }
        });
    });
}