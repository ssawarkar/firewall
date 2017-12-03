/**
 * Created by suraj on 15/08/2016.
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
var controller = "bsconfigv7stats";
var option = "com_ose_firewall";
var browsers = {};
var attackTypes = new Array();
var browserStats = new Array();
var monthStats = new Array();
var geoStats = new Array();
var timeChart;
var temp;
var dailyStats = new Array();
var dailyChart;
jQuery(document).ready(function($){
    showLoading("Loading statistics");
    getStats();
    $('#time-chart').click(function(evt){
        var activePoints = timeChart.getElementsAtEvent(evt);
        var firstPoint = activePoints[0];
        console.log(firstPoint);
        if (firstPoint !== undefined) {
            temp = monthStats.monthstats_keys[firstPoint._index];
            var timedate = temp.split("/");
            getDailyStats(timedate[0],timedate[1]);
        }
    });

    $('#go-current-month-chart').click(function(){
       $('#daily-chart').fadeOut();
        $('#daily-chart').remove();
        $('#time-chart').fadeIn();
    });
});

function drawCharts() {
    drawBrowserChart();
    drawTimeChart();
    drawTypeChart();
    drawIPChart();
}

function drawBrowserChart() {
    //alert(JSON.stringify(browserStats));
    jQuery(document).ready(function($){
        var ctx = $('#browser-chart');
        var data = {
            labels:browserStats.browser_keys,
            datasets: [
                {
                    data:browserStats.browser_values,
                    backgroundColor: [
                        "#FF6384",
                        "#36A2EB",
                        "#fcbc49",
                        "#af90b4",
                        "#f32929"
                    ],
                    hoverBackgroundColor: [
                        "#FF6384",
                        "#36A2EB",
                        "#fcbc49",
                        "#af90b4",
                        "#f32929"
                    ],
                    borderColor:[
                        'rgba(255, 99, 132, 0.1)',
                        'rgba(255, 99, 132, 0.1)',
                        'rgba(255, 99, 132, 0.1)',
                        'rgba(255, 255, 255, 0.8)',
                        'rgba(255, 255, 255, 0.1)'
                    ],
                    borderWidth:[
                        1,1,1,2,1
                    ]
                }]
        };
        var myChart = new Chart(ctx, {
            type: 'pie',
            data: data,
            options: {
                legend: {
                    position:'right',
                    labels:{
                        fontColor:"white",
                        fontSize: 12
                    }
                }
            }
        });
    });

}
function drawTimeChart() {
jQuery(document).ready(function($){
    var ctx = $('#time-chart');
    var data = {
        labels:monthStats.monthstats_keys,
        datasets: [
            {
                label: "Number of attack detected",
                fill: true,
                lineTension: 0.1,
                backgroundColor: "rgba(34,217,175,0.1)",
                borderColor: "rgba(34,217,175,0.5)",
                borderCapStyle: 'butt',
                borderDash: [],
                borderDashOffset: 0.0,
                borderJoinStyle: 'miter',
                pointBorderColor: "rgba(75,192,192,1)",
                pointBackgroundColor: "#fff",
                pointBorderWidth: 8,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: "rgba(75,192,192,1)",
                pointHoverBorderColor: "rgba(220,220,220,1)",
                pointHoverBorderWidth: 2,
                pointRadius: 1,
                pointHitRadius: 10,
                data:monthStats.monthstats_values,
                spanGaps: false
            }
        ]
    };

    var myLineChart = new Chart(ctx, {
        type: 'line',
        data: data,
        options: {
            title: {
                display: true,
                position:'bottom',
                text: 'Monthly ( 30 Days ) Attack Analysis',
                fontColor:'white',
                fontStyle:'400'
            },
            legend:{
                display:false
            },
            scales: {
                xAxes: [{
                    gridLines:{
                        color:"rgba(255,255,255,0.3)",
                        zeroLineColor:"rgba(255,255,255,0.8)"
                    },
                    ticks: {
                        fontColor: "rgba(255,255,255,0.9)", // this here
                        fontSize:13
                    }
                }],
                yAxes: [{
                    gridLines:{
                        color:"rgba(255,255,255,0.3)",
                        zeroLineColor:"rgba(255,255,255,0.5)"
                    },
                    ticks: {
                        fontColor: "rgba(255,255,255,0.9)", // this her
                        min: 0,
                        fontSize:13

                    }
                }]
            }
        }
    });

    timeChart = myLineChart;

});
}
function drawDailyStats() {
    jQuery(document).ready(function ($) {
        $('#daily-chart-container').append(' <canvas id="daily-chart" class="col-sm-12"></canvas>');
        var ctx = $('#daily-chart');
        var data = {
            labels:dailyStats.label,
            datasets: [
                {
                    label: "Number of attack detected ",
                    fill: true,
                    lineTension: 0.1,
                    backgroundColor: "rgba(34,217,175,0.1)",
                    borderColor: "rgba(34,217,175,0.5)",
                    borderCapStyle: 'butt',
                    borderDash: [],
                    borderDashOffset: 0.0,
                    borderJoinStyle: 'miter',
                    pointBorderColor: "rgba(75,192,192,1)",
                    pointBackgroundColor: "#fff",
                    pointBorderWidth: 8,
                    pointHoverRadius: 5,
                    pointHoverBackgroundColor: "rgba(75,192,192,1)",
                    pointHoverBorderColor: "rgba(220,220,220,1)",
                    pointHoverBorderWidth: 2,
                    pointRadius: 1,
                    pointHitRadius: 10,
                    data:dailyStats.value,
                    spanGaps: false
                }
            ]
        };

         dailyChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                title: {
                    display: true,
                    position:'bottom',
                    text: 'Specific Day ( 24 Hours ) Attack Analysis',
                    fontColor:'white',
                    fontStyle:'400'
                },
                legend:{
                    display:false
                },
                scales: {
                    xAxes: [{
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,0.8)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,0.9)", // this here
                            fontSize:13
                        }
                    }],
                    yAxes: [{
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,0.5)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,0.9)", // this her
                            min: 0,
                            fontSize:13

                        }
                    }]
                }
            }
        });
    });
}
function drawIPChart() {
    jQuery(document).ready(function($){
        var ctx = $('#ip-chart');
        var data = {
            labels: geoStats.countryLabel,
            datasets: [

                {
                    backgroundColor:'rgba(75, 192, 192, 0.8)',
                    label: "Cross Site Scripting",
                    fillColor: "blue",
                    data: geoStats.data.CrossSiteScripting
                },
                {
                    backgroundColor:'rgba(10, 20, 200, 0.5)',
                    label: "Cross Site Request Forgery",
                    fillColor: "red",
                    data: geoStats.data.CrossSiteRequestForgery
                },
                {
                    backgroundColor:"#af90b4",
                    label: "SQL Injection",
                    fillColor: "purple",
                    data: geoStats.data.SQLInjection
                },
                {
                    backgroundColor:'rgba(255, 206, 86, 0.8)',
                    label: "Remote File Inclusion",
                    fillColor: "green",
                    data:  geoStats.data.RemoteFileInclusion
                },
                {
                    backgroundColor:'rgba(255, 99, 132, 0.8)',
                    label: "Local File Inclusion",
                    fillColor: "violet",
                    data:  geoStats.data.LocalFileInclusion
                },
                {
                    backgroundColor:'rgba(54, 162, 235, 0.8)',
                    label: "Layer 2 Intrusion",
                    fillColor: "indigo",
                    data:  geoStats.data.Layer2Intrusion
                },
                {
                    backgroundColor:'rgba(153, 102, 255, 0.8)',
                    label: "Directory Traversal",
                    fillColor: "blue",
                    data:  geoStats.data.DirectoryTraversal
                },
                {
                    backgroundColor:'rgba(255, 99, 132, 0.8)',
                    label: "Local File Modification Attempt",
                    fillColor: "green",
                    data:  geoStats.data.LocalFileModificationAttempt
                },
                {
                    backgroundColor:'rgba(54, 162, 235, 0.8)',
                    label: "Spamming",
                    fillColor: "yellow",
                    data:  geoStats.data.Spamming
                },
                {
                    backgroundColor:'rgba(255, 206, 86, 0.8)',
                    label: "Format String Attack",
                    fillColor: "orange",
                    data:  geoStats.data.FormatStringAttack
                },
                {
                    backgroundColor:'#ff4b4a',
                    label: "Inconsistent File Type",
                    fillColor: "red",
                    data:  geoStats.data.InconsistentFileType
                },
                {
                    backgroundColor:'#ff4b4a',
                    label: "Virus File",
                    fillColor: "blue",
                    data:  geoStats.data.VirusFile
                },
                {
                    backgroundColor:'#ff4b4a',
                    label: "Brute Force Protection",
                    fillColor: "orange",
                    data:  geoStats.data.BruteForceProtection
                }
                //{
                //    backgroundColor:'#ff4b4a',
                //    label: "Undefined attack",
                //    fillColor: "green",
                //    data:  geoStats.data.CrossSiteScripting
                //},


            ]
        };
        var myBarChart = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                legend:{
                    display:false
                },
                scales:{
                    xAxes: [{
                        stacked: true,
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,08)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,1)", // this here
                            fontSize:13,
                        }

                    }],
                    yAxes: [{
                        stacked: true,
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,0.5)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,1)", // this her
                            //max: 20,
                            //min: 0,
                            //stepSize: 4,
                            fontSize:13

                        }
                    }]
                }
            }
        });
    });

}
function drawTypeChart() {
    var a = new Array();
     a = ["Cross Site Scripting", "Cross Site Request Forgery", "SQL Injection", "Remote File Inclusion",
        "Local File Inclusion", "Layer 2 Intrusion", "Directory Traversal",
        "Local File Modification Attempt", "Spamming", "Formate String Attack", "Inconsistent File Type",
        "Virus File","Brute Force Protection","Other"]
    jQuery(document).ready(function($) {
        var ctx = $('#types-chart');
        var data = {
            labels:attackTypes.attacktype_keys,
            datasets: [
                {
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(255, 159, 64, 0.8)',
                        'rgba(255, 159, 64, 0.8)',

                    ],

                    data:attackTypes.attacktype_values,
                }
            ]
        };
        var myBarChart = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                legend:{
                    display:false
                },
                scales:{
                    xAxes: [{
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,0.8)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,1)", // this here
                            fontSize:10,
                            autoSkip:false,
                        }

                    }],
                    yAxes: [{
                        gridLines:{
                            color:"rgba(255,255,255,0.3)",
                            zeroLineColor:"rgba(255,255,255,0.5)"
                        },
                        ticks: {
                            fontColor: "rgba(255,255,255,1)", // this her
                            max: 10,
                            min: 0,
                            stepSize: 1,
                            autoSkip:false,

                        }
                    }]
                }
            }
        });
    });
}



function getStats()
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                action: 'getStats',
                task: 'getStats',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {
                    hideLoading();
                    attackTypes = data.info.attacktype;
                    browserStats = data.info.browser;
                    monthStats = data.info.datestats;
                    geoStats = data.info.geoStats;
                    drawCharts();

                }else if(data.status == 2)
                {
                    //geo db is not installed
                    hideLoading();

                    swal({
                            title:'<span class="text-danger">'+O_COUNTRY_DATABASE_NOT_INSTALLED+'</span>',
                            text: data.info ,
                            html: true,
                            confirmButtonColor: "#6bc4b5",
                            confirmButtonText: "Cancel",
                            closeOnConfirm: true
                        },
                        function(){
                            $('.browser-chart-height').css('height','300px');
                            $('.fs-nodata').show();
                        });
                }
                else {
                    hideLoading();
                    $('.browser-chart-height').css('height','300px');
                    $('.fs-nodata').show();
                }

            }
        })
    });
}

//pass the month and the day
function getDailyStats(month,day)
{
    jQuery(document).ready(function ($) {
        $.ajax({
            type: "GET",
            url: url,
            dataType: 'json',
            data: {
                option: option,
                controller: controller,
                month : month,
                date:day,
                action: 'getDailyStats',
                task: 'getDailyStats',
                centnounce: $('#centnounce').val()
            },
            success: function (data) {
                if(data.status == 1)
                {

                    $('#time-chart').fadeOut();
                    hideLoading();
                    dailyStats = data.info;
                    console.log(dailyStats);
                    drawDailyStats();
                    $('#daily-chart').fadeIn();
                    //show graph

                }else {
                    hideLoading();
                    showDialogue(data.info,"ERROR","close");
                }

            }
        })
    });
}
