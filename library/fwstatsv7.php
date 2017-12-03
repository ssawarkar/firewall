<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 20/07/2016
 * Time: 2:21 PM
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
if (!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
define('WEBLOG_ALLOWED_DAYS',30);
define('WEBLOGBACkUP_ALLOWED_MONTHS',3);
oseFirewall::loadJSON ();
class fwstatsv7{
    public $browser_stats = array();
    public $attacktype_stats = array();
    public $date_stats = array();
    public $month_stats = array();
    public $year_stats = array();
    public $hour_stats = array();
    public $ip_stats = array();
    public  $datetime_stats = array();
    public $weekly_stats = array();
    public $geo_stats = array();
    public static $dateStats = array();

    public function __construct($qatest = false)
    {
        $this->qatest = $qatest;
        $this->db = oseFirewall::getDBO();
        $this->prerequisistes();
    }
    public function prerequisistes()
    {
        oseFirewall::callLibClass('fwscannerv7','fwscannerv7');
        $this->fwscanner = new oseFirewallScannerV7();
        oseFirewall::callLibClass('fwscannerv7','ipManagement');
        $this->ipmanagement = new ipManagement();
    }

    public function getAttackFileContent($ip)
    {
        $attackrecord = null;
        $filepath = OSE_WEBLOGFOLDER.ODS.$ip.ODS.'blocked.php';
        if(file_exists($filepath))
        {
            $content = $this->fwscanner->getAttackFilecontent($ip);
            return $content;
        }else {
            return false;
        }
    }

    //gets the name of attacks based on the id of the attack
    public function getAttackName($key)
    {
        switch($key)
        {
            case '2': return 'Cross Site Scripting'; break;
            case '3': return 'Cross Site Request Forgery'; break;
            case '4': return 'SQL Injection'; break;
            case '5': return 'Remote File Inclusion'; break;
            case '6': return 'Local File Inclusion'; break;
            case '7': return 'Layer 2 Intrusion'; break;
            case '8': return 'Directory Traversal'; break;
//            case '9': return 'Denial of Service Attack'; break;
            case '10': return 'Local File Modification Attempt'; break;
            case '11': return 'Spamming'; break;
            case '12': return 'Format String Attack'; break;
            case '13': return 'Inconsistent File Type'; break;
            case '14': return 'Virus File'; break;
            case '15': return 'Brute Force Protection'; break;
            default:
                return 'Undefined attack';
                break;
        }
    }

    //return an array with the name of all the attacks from their ids
    public function getAttackNameList($arrayList)
    {
        $result = array();
        foreach($arrayList as $record)
        {
            $name = $this->getAttackName($record);
            array_push($result,$name);
        }
        return $result;
    }


    public function preapreAttackInfoContent($ip)
    {
        $attackInfo_temp = $this->getAttackFileContent($ip);
        $blocked =$this->ipmanagement->isIPBlockedDB($ip);
        if($attackInfo_temp == false && $blocked)
        {
            return $this->fwscanner->prepareSuccessMessage("The ip has been manually blocked by the user");
        }elseif($attackInfo_temp == false && $blocked == false) {
            return $this->fwscanner->prepareSuccessMessage("Record does not exists for the IP: ".$ip);
        }
        else
        {
         $temp_last_record =end(array_keys($attackInfo_temp));
         $finalcontent = "<b>IP Address : ".$ip."</b><br/>";
            $finalcontent.="<table border=\"1\" cellpadding=\"10\" cellspacing=\"1\"><tr>
                        <th class=\"shrink\">".oLang::_get('O_URL')."</th>
                        <th class=\"shrink\">".oLang::_get('O_REFERER')."</th>
                        <th class=\"shrink\">".oLang::_get('O_DATETIME')."</th>
                        <th class=\"shrink\">".oLang::_get('TYPE_OF_ATTACK')."</th>
                        <th class=\"shrink\">".oLang::_get('STRING_DETECTED')."</th>
                        <th class=\"shrink\">".oLang::_get('O_DETECTED_VAR')."</th>
                        <th class=\"shrink\">".oLang::_get('FILES_UPLOAD_REQUEST')."</th>
                        <th class=\"shrink\">".oLang::_get('SCORE')."</th>
                         <th class=\"shrink\">".oLang::_get('ATTEMPTS')."</th>
                        </tr>";
            $finalcontent.= "<tr>";
         foreach($attackInfo_temp as $key=>$record)
         {
             $finalcontent.= $this->formatAttackInfoContentsParamas($record['url']);
             $finalcontent.= $this->formatAttackInfoContentsParamas($record['referer']);
             $temp1 =$this->formatDateViewBlockeIp($record['attackdatetime']);
             $finalcontent.= $this->formatAttackInfoContentsParamas($temp1);
             $attackname_temp = $this->getAttackNameList($record['attacktype']);
             $finalcontent.= $this->formatAttackInfoContentsParamas($attackname_temp,true);
             $finalcontent.= $this->formatAttackInfoContentsParamas($record['attack']);
             $finalcontent.= $this->formatAttackVars($record['variables']);
             $temp_file_contents = $this->formatFileUploadAttackVars($record['files']);
             $finalcontent.= $this->getTableContentFileUpload($temp_file_contents);
             if($temp_last_record ==$key)
             {
                 //last record highlight the score and attempts
                 $finalcontent.= "<td><span class='text-danger'>".$record['score']."</span></td>";
                 $finalcontent.= "<td><span class='text-danger'>".$record['attempt']."</span></td>";

             }else{
                 $finalcontent.= "<td>".$record['score']."</td>";
                 $finalcontent.= "<td>".$record['attempt']."</td>";
             }
             $finalcontent.= "</tr>";

         }
            $finalcontent.="</table>";
            $result['info'] = $finalcontent;
            $result['status'] = 1;
            return $result;
        }
    }

    public function formatAttackInfoContentsParamas($valuesArray,$list = false)
    {
        if(empty($valuesArray))
        {
            return "<td>N/A</td>";
        }
         if(is_array($valuesArray))
         {
             if($list!=false)
             {
                 $finalString = "<td class='shrink'><ul style=\"line-height: 21px;\">";
                 foreach($valuesArray as $attackname)
                 {
                     $finalString.= "<li>".$attackname."</li>";
                 }
                 $finalString.="</ul></td>";
             }else
             {
                 $strings = implode("<br/>",$valuesArray);
                 $finalString = "<td class=\"shrink\">".$strings."</td>";
             }

             return $finalString;
         }else{
             return "<td class=\"shrink\">".$valuesArray."</td>";
          }
    }

    public function formatAttackVars($valuesArray,$list = false)
    {
        if(empty($valuesArray))
        {
            return "<td>N/A</td>";
        }
        if(is_array($valuesArray))
        {
            if(count($valuesArray) == 1)
            {
                $temp_strings = explode('#',$valuesArray[0]);
                $strings = $temp_strings[0];
            }else{
                $temp_string = $valuesArray;
                $strings = implode("",$temp_string);
            }
            $finalString = '<td class=\'shrink\' ><a href=\'javascript:void(0);\' title = \'Click to white List the variable\' onClick="whitelist_confirm(\'' . $strings . '\')">'.$strings."</a></td>";
            return $finalString;
        }else{
            if($valuesArray=="N/A")
            {
                $finalString = '<td class=\'shrink\'>'.$valuesArray."</a></td>";
            }else{
                $temp_strings = explode('#',$valuesArray[0]);
                $finalString = '<td class=\'shrink\' ><a href=\'javascript:void(0);\' title = \'Click to white List the variable\' onClick="whitelist_confirm(\'' . $temp_strings[0] . '\')">'.$temp_strings[0]."</a></td>";
            }
            return $finalString;
        }
    }

    public function getTableContentFileUpload($fileUploadArray)
    {
        $temp_content ='';
        if(empty($fileUploadArray))
        {
            return "<td>N/A</td>";
        }else{
            $temp_content  = "<td class='shrink'><ul style=\"line-height: 21px;\">";
            foreach($fileUploadArray as $key=>$var)
            {
                $temp_content.= "<li>".$key."=>".$var."</li>";
            }
            $temp_content.="</ul></td>";
            return $temp_content;
        }
    }

    public function formatFileUploadAttackVars($valuesArray)
    {
        if(empty($valuesArray))
        {
           return false;
        }else{
            $flatArray = $this->flattenArray($valuesArray);
            return $flatArray;
        }
    }


    public function flattenArray($arrayVar)
    {
        if (!is_array($arrayVar)) {
            return FALSE;
        }
        $result = array();
        foreach ($arrayVar as $key => $value) {
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value));
            }
            else {
                $result[$key] = $value;
            }
        }
        return $result;
    }

    public function formatDateViewBlockeIp($attackdatetime)
    {
        $return = array();
        foreach($attackdatetime as $key =>$record)
        {
            $date = substr($record, 0, 2);
            $month = substr($record, 2, 2);
            $year = substr($record, 4, 2);
            $content = $date.'/'.$month.'/'.$year;
           $return[$key]=$content;
        }
        if(!empty($return))
        {
            $countvalues = array_count_values($return);
            if(!empty($countvalues))
            {
                $return_result = array();
                foreach($countvalues as $key=>$val)
                {
                    $return_result[$key] = $key ;//.'==> '.$val .' attempt(s)';
                }
                return $return_result;
            }
        }else {
            //empty
            return false;
        }
    }


    function formatAssociateArray($attributes)
    {
        $dataAttributes = array_map(function($value, $key) {
            return $key.'="'.$value.'"';
        }, array_values($attributes), array_keys($attributes));

        $dataAttributes = implode('<br/>', $dataAttributes);
        return $dataAttributes;
    }

    //used by ip managem,ent
    public function prepareModal($content)
    {
        $temp = "<div width='100%' class='form-horizontal group-border stripped'>
                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('ATTACK_INFORMATION')."</label>
                    </div>
                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('IP_ADDRESS')."</label>
                        <div class='col-sm-9'>".$content['ip']."
                        </div>
                    </div>

                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('Date')."</label>
                        <div class='col-sm-9'>".$content['datetime']."
                        </div>
                    </div>

                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('TYPE_OF_ATTACK')."</label>

                    <div class='col-sm-9'>".$content['attackname']."
                        </div>
                    </div>
                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('STRING_DETECTED')."</label>
                        <div class='col-sm-9'>".$content['warningtext']."
                        </div>
                    </div>
                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('SCANNED_VARIABLES')."</label>
                        <div class='col-sm-9'>".$content['variables']."
                        </div>
                    </div>
                    <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('FILES_UPLOAD_REQUEST')."</label>
                        <div class='col-sm-9'>".$content['uploadfile']."
                        </div>
                    </div>
                     <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('SCORE')."</label>
                        <div class='col-sm-9'>".$content['score']."
                        </div>
                    </div>
                     <div class='form-group'>
                        <label class='col-sm-3 control-label'>".oLang::_get('ATTEMPTS')."</label>
                        <div class='col-sm-9'>".$content['attempt']."
                        </div>
                    </div>
                    ";
        $result['info'] = $temp;
        $result['status'] = $content['status'];
        return $result;
    }


    //prepares an aray of all the blocked files
    public function prepareStatisticsContent()
    {
        $blockFileContent = array();
        $filesList = $this->fwscanner->prepareListOfattackFiles();
        foreach($filesList as $files)
        {
            if(basename($files) == 'blocked.php')
            {
                oseFirewall::callLibClass('fwscannerv7','fwscannerv7');
                $fwscannerv7 = new oseFirewallScannerV7();
                $content = $fwscannerv7->getCompleteAttackInformation(false,$files);
//                $content = $this->getBlockedFileContent($files);
                array_push($blockFileContent,$content);
            }
        }
        return $blockFileContent;
    }



    public function getBlockedFileContent($filepath)
    {
        if(file_exists($filepath)){
            $attackrecord = array();
            require($filepath);
            return $attackrecord;
        }else {
            return false;
        }

    }

    //COMPLETE METHOD
    public function getAttackStatistics()
    {
        $temp = array();
        $result_attackTypeStats = array();
        //check geo ip db to get access to the geo/ip stats
        if ($this->geoDBExists() == true) {
            $blockedFileContent = $this->prepareStatisticsContent();
            //push all the elemets into an array to get a complete list of the attack entries
            foreach ($blockedFileContent as $blockFile) {
                if (isset($blockFile['browser'])) {
                    $this->browser_stats = $this->formatStatsContent($blockFile['browser'], $this->browser_stats);
                }
                if (isset($blockFile['attacktype'])) {
                    $this->attacktype_stats = $this->formatStatsContent($blockFile['attacktype'], $this->attacktype_stats);

                }
                if (isset($blockFile['attackdatetime'])) {
                    $this->formatDateTime($blockFile['attackdatetime']);

                }
                if (isset($blockFile['ip'])) {
                    $this->getGeoStats($blockFile);
                }

            }
            //BROWSER
            $browser_result = $this->getBrowserStats($this->browser_stats);
            if ($browser_result == false) {
                return $this->prepareCustomMessage(0, 'The browser stats are blank');
            }
            //ATTACK TYPE
            $attackType_result = $this->getAttackTypeStatsFormat($this->attacktype_stats);
            if ($attackType_result == false) {
                return $this->prepareCustomMessage(0, 'The AttackType stats are blank');
            }
            //TIME ANALYSIS
            self::$dateStats = $this->datetime_stats;
            $month_stats = $this->getFormattedMonthAnalysis();
            if ($month_stats == false) {
                return $this->prepareCustomMessage(0, 'The Month stats are blank');
            }
            //IP ANALYSIS
            $geo_stats = $this->getStatFormatGeoStats();
            $statsEmpty = $this->checkGeoStatsIsEmpty($geo_stats);
            if ($statsEmpty) {
                $result['status'] = 0;
                $result['info'] = 'The GEO/IP stats are blank';
                return $result;
            } else {
                $result['browser'] = $browser_result;
                $result['attacktype'] = $attackType_result;
                $result['datestats'] = $month_stats;
                $result['geoStats'] = $geo_stats;
                $result_final = $this->isStatsEmpty($result);
                return $result_final;
            }
        }else {
                //geo db is not installed
                $result['status'] = 2;
                if(OSE_CMS == 'joomla')
                {
                    $link = '<a href="?option=com_ose_firewall&view=countryblockingv7">Country Database</a>';
                }else {
                    $link = ' <a href="admin.php?page=ose_fw_countryblockingv7"> Country Database</a>';
                }
                $result['info'] = 'Please click on Download Country Database from this Link : '.$link. '<br/> Revisit the Firewall Statistics page to view the Website Statistics ';
                return $result;
             }

    }

    //check if the geo databse table exista and its not empty
    public function geoDBExists()
    {
       $tableExist = $this->db->isTableExists('#__ose_app_geoip');
        if($tableExist) {
            $query = 'SELECT COUNT(`id`) as count from `#__ose_app_geoip`';
            $this->db->setQuery($query);
            $temp = $this->db->loadObject();
            if ($temp->count > 1) {
                return true;
            } else {
                return false;
            }
        }else {
            return false;
        }
    }
    public function checkGeoStatsIsEmpty($geo_stats)
    {
        if(empty($geo_stats['countryLabel']) && empty($geo_stats['data']))
        {
            return true;
        }else {
            return false;
        }
    }

    public function getBrowserStats($browserArray)
    {
        //BROWSER FORMATTING
        //format the browser types
        if(!empty($browserArray)) {
            $browserArray = $this->setOtherBrowserTypes($browserArray);
            $browser_count = array_count_values($browserArray);
            //set the other types as 0
            $browser_result = $this->formatBrowserTypes($browser_count);
            $browser_result = array_merge($browser_count, $browser_result);
            //remove white spaces from the keys
            $browser_result = $this->trimWhiteSpaces($browser_result);
            $result = $this->getLabelValueArray('browser', $browser_result);
            return $result;
        }else {
            return false;
        }
    }

    public function setOtherBrowserTypes($browserArray)
    {
        $temp =array();
        foreach($browserArray as $id=>$browsername)
        {
            if($browsername == 'Edge')
            {
                $temp[$id] = 'Other';
            }else {
                $temp[$id] = $browsername;
            }
        }
        return $temp;
    }

    public function getLabelValueArray($type,$array)
    {
        $result = array();
        $result[$type.'_keys'] = array_keys($array);
        $result[$type.'_values'] = array_values($array);
        return $result;
    }

    public function getAttackTypeStatsFormat($attackTypeArray)
    {
        if(!empty($attackTypeArray)) {
            $count = array_count_values($attackTypeArray);
            $result_attackTypeStats = $this->getAttackTypeStatsName($count);
            //ATTACK TYPE FORMATIING
            //set the other types as 0
            $attackType_result = $this->formatAttackType($result_attackTypeStats);
            $attackType_result = array_merge($result_attackTypeStats, $attackType_result);
            //remove white spaces from the keys
//        $attackType_result = $this->trimWhiteSpaces($attackType_result);
            $attackType_result = $this->getLabelValueArray('attacktype', $attackType_result);
            return $attackType_result;
        }else {
            return false;
        }
    }

    public function formatBrowserTypes($data)
    {
        $temp = array();
        $browserArray = array('Opera','Chrome','Safari','Firefox','Internet Explorer','Other');
        foreach($browserArray as $browser)
        {
            if(!array_key_exists($browser,$data))
            {
              $temp[$browser] = 0;
            }
        }
        return $temp;

    }

    public function formatAttackType($data)
    {
        $temp = array();
        $attackTypeArray = array('Cross Site Scripting','Cross Site Request Forgery','SQL Injection','Remote File Inclusion','Local File Inclusion','Layer 2 Intrusion','Directory Traversal','Local File Modification Attempt','Spamming','Formate String Attack','Inconsistent File Type','Virus File','Brute Force Protection','Undefined Attack');
        foreach($attackTypeArray as $attackType)
        {
            if(!array_key_exists($attackType,$data))
            {
                $temp[$attackType] = 0;
            }
        }
        return $temp;

    }
    public function trimWhiteSpaces($data)
    {
        $result =array();
        foreach($data as $key=>$value)
        {
            $result[str_replace(' ', '', $key)] = $value;
        }
        return $result;
    }

    public function formatStatsContent($fileContent,$statsVariable)
    {
        if (is_array($fileContent)) {
            $statsVariable = array_merge($statsVariable,$fileContent);
        } else {
            array_push($statsVariable, $fileContent);
        }
        return $statsVariable;
    }


    public function prepareCustomMessage($status,$msg)
    {
        $result['status'] = $status;
        $result['info'] = $msg;
        return $result;
    }

    public function isStatsEmpty($stats)
    {
        foreach($stats as $key=>$value)
        {
          if(empty($value))
          {
              return $this->prepareCustomMessage(0,'There was some problem in generating the statistics for :'.$key);
          }
        }
        return $this->prepareCustomMessage(1, $stats);
    }

    public function getAttackTypeStatsName($array)
    {
        $temp = array();
        foreach($array as $attackId=>$attackCount)
        {
            $attackName = $this->getAttackName($attackId);
            $temp[$attackName] = $attackCount;
        }
        return $temp;
    }


    public function formatDateTime($fileContent)
    {

        //not an array
        $result = array();
        $current_date = date('d');
        $current_month = date('m');
        if(is_array($fileContent))
        {
            foreach ($fileContent as $datetime)
            {
                $date = substr($datetime, 0, 2);
                $month  = substr($datetime, 2, 2);
                $hour = substr($datetime, 6, 2);
                if(isset($this->datetime_stats[$month][$date][$hour]))
                {
                    $this->datetime_stats[$month][$date][$hour] = $this->datetime_stats[$month][$date][$hour] + 1;
                }else {
                    $this->datetime_stats[$month][$date][$hour] = 1;
                }
            }
        }else {
            //not an array
            $date = substr($fileContent, 0, 2);
            $month  = substr($fileContent, 2, 2);
            $hour = substr($fileContent, 6, 2);
            if(isset($this->datetime_stats[$month][$date][$hour]))
            {
                $this->datetime_stats[$month][$date][$hour] = $this->datetime_stats[$month][$date][$hour] + 1;
            }else {
                $this->datetime_stats[$month][$date][$hour] = 1;
            }
        }
        $result['currentDate'] = $current_date;
        $result['currentMonth'] = $current_month;
        $result['info'] = $this->datetime_stats;  //chnage this to send only the current date and time
        return $result;
    }



    public function getMonthStats()
    {
        $currentMonth = date('m');
        $currentDate = date('d');
        $result = array();
        if(!empty($this->datetime_stats)){
        foreach($this->datetime_stats as $month =>$daysrecords)
        {
            foreach($daysrecords as $dayKey=>$day)
            {
                $result[$month][$dayKey] = array_sum($day);
            }
        }
        if(!empty($result))
        {
            $result['currentMonth'] = $currentMonth;
            $result['currentDate'] = $currentDate;
            $result1 =  $this->prepareCustomMessage(1,$result);
            return $result1;
        }else {
            return $this->prepareCustomMessage(0,'There was some problem in generating the monthly stats');
        }
        }else {
            return false;
        }

    }

    public function getFormattedMonthAnalysis()
    {
        $result_datestats = array();
        $monthStatsArray = $this->getMonthStats();
        if($monthStatsArray ==false){
           return false;
        }else {
            $now = new DateTime();
            $back = $now->sub(DateInterval::createFromDateString('30 days'));
            $startDate = $back->format('d-m-y');
            $startDateArray = explode('-', $startDate);
            $startMonth = $startDateArray[1];
            $startDate = $startDateArray[0];
            $startYear = $startDateArray[2];
//            $noOfDaysInMonth = cal_days_in_month(CAL_GREGORIAN, $startMonth, $startYear);
            $noOfDaysInMonth = date('t', mktime(0, 0, 0, $startMonth, 1, $startYear));
            $current = date('d-m-y');
            $currentDateArray = explode('-', $current);
            $currentDate = $currentDateArray[0];
            $currentMonth = $currentDateArray[1];
            $currentYear = $currentDateArray[2];
//            $Current_noOfDaysInMonth = cal_days_in_month(CAL_GREGORIAN, $currentMonth, $currentYear);
            $Current_noOfDaysInMonth = date('t', mktime(0, 0, 0, $currentMonth, 1, $currentYear));
            if ($startMonth < $currentMonth) {
                $result1 = $this->generateFormattedMonthStats($startDate, $startMonth, $noOfDaysInMonth, $monthStatsArray['info']);
                $result2 = $this->generateFormattedMonthStats('01', $currentMonth, $currentDate, $monthStatsArray['info']);
                $result_datestats = array_merge($result1, $result2);
            }
            if ($startMonth == $currentMonth) {
                $result_datestats = $this->generateFormattedMonthStats('01', $currentMonth, $noOfDaysInMonth, $monthStatsArray['info']);
            }

            $result = $this->getLabelValueArray('monthstats', $result_datestats);
            return $result;
        }
    }

    //return the stats for 24 hours for a day
    public function getAnalysisofDay($day,$month)
    {

        $blockedFileContent = $this->prepareStatisticsContent();
        if(!empty($blockedFileContent)) {
            //push all the elemets into an array to get a complete list of the attack entries
            foreach ($blockedFileContent as $blockFile) {
                if (isset($blockFile['attackdatetime'])) {
                    $this->formatDateTime($blockFile['attackdatetime']);
                }
            }

            $result = array();
            $temp = array();
            $range = range(00, 24);
            $original = $this->datetime_stats;
            if (empty($original)) {
                return $this->prepareCustomMessage(0, 'Daily stats are not available for ' . $day . '/' . $month);
            } else {
                $original = $this->datetime_stats[$month][$day];
                foreach ($range as $rec) {
                    if (!array_key_exists($rec, $original)) {
                        $temp[$rec] = 0;
                    }
                }
                $result = $original + $temp;
                ksort($result);
                if (!empty($result)) {
                    $formattedContent = $this->formatDailyStatsContent($result);
                    return $this->prepareCustomMessage(1, $formattedContent);
                } else {
                    return $this->prepareCustomMessage(0, 'There are no stats for ' . $day . '/' . $month);
                }
            }
        }
        else {
            return $this->prepareCustomMessage(0, 'There are no stats for ' . $day . '/' . $month);
        }
    }

    public function formatDailyStatsContent($stats)
    {
        $result =array();
        foreach($stats as $time=>$attempts)
        {
            $result[$time.':00'] =$attempts;
        }
        $key = array_keys($result);
        $values = array_values($result);
        $result1['label'] =$key;
        $result1['value'] =$values;
        return $result1;
    }

    public function generateFormattedMonthStats($startDate,$startMonth,$noOfDaysInMonth,$monthStatsArray)
    {
        $result = array();
         if(array_key_exists($startMonth,$monthStatsArray))
         {
             for($i = $startDate;$i<=$noOfDaysInMonth;$i++)
             {
                 $date_i = $this->formatStartDate($i);
                 if(array_key_exists($date_i,$monthStatsArray[$startMonth]))
                 {

                  $result[$date_i.'/'.$startMonth] = $monthStatsArray[$startMonth][$date_i];
                 }else {
                     $result[$date_i.'/'.$startMonth] = 0;
                 }
             }
         }else {
             for($i = $startDate;$i<=$noOfDaysInMonth;$i++)
             {
                 $date_i = $this->formatStartDate($i);
                 $result[$date_i.'/'.$startMonth] = 0;
             }
         }
        return $result;
    }

    public function formatStartDate($date)
    {
        if(strlen($date) == 1)
        {
            return ('0'.$date);
        }else {
            return $date;
        }
    }
    public function gethourlyStats($month,$date)
    {
        $hourstats= $this->datetime_stats[$month][$date];
        if(!empty($hourstats))
        {
            $result['status'] = 1;
            $result['info'] = $hourstats;
        }else {
            $result['status'] = 0;
            $result['info'] = 'There is non data for the month '.$month.' and date '.$date;
        }
        return $result;
    }

    public function getGeoStats($blockedFileContent)
    {
        oseFirewallBase::callLibClass('CountryBlock','CountryBlock');
        $countryBlock = new CountryBlock();
        $country_code = $countryBlock->getCountryCode(ip2long(($blockedFileContent['ip'])));
        if($country_code !== false)
        {
            //attetmps part
            if(isset($this->geo_stats[$country_code]['attempt'])){
                $this->geo_stats[$country_code]['attempt'] = $this->geo_stats[$country_code]['attempt'] + $blockedFileContent['attempt'];
            }else {
                $this->geo_stats[$country_code]['attempt'] = $blockedFileContent['attempt'];
            }
            //attack distribution part

            $this->prepareAttackTypeArray($country_code,$blockedFileContent['attacktype']);
        }

    }

    //suraj
    public function getFormattedGeoStats()
    {
        $result = array();
        foreach($this->geo_stats as $key=>$record)
        {
            if(isset($record['attacktype']))
            {
                foreach($record['attacktype'] as $attackNo=>$attackCount)
                {
                    $attackName = $this->getAttackName($attackNo);
                    if(isset($result[$key]['attacktype'][$attackNo] ))
                    {
                        $result[$key]['attacktype'][$attackNo] = $result[$key]['attacktype'][$attackNo] + $attackCount;
                    }else {
                        $result[$key]['attacktype'][$attackNo] = $attackCount;
                    }

                }

                $missingelements = $this->fillNonExistingAtttacksWithValues($result[$key]['attacktype']);

                $attackTypeArray = ($result[$key]['attacktype'] + $missingelements);
                ksort($attackTypeArray);
                $result[$key]['attacktype'] = $attackTypeArray;
                $result[$key.'#attetmpscount'] = array_sum(($attackTypeArray));
            }
        }

        return $result;
    }



    public function getStatFormatGeoStats()
    {
        $result = array();
        $data = $this->getFormattedGeoStats();
        $sortedArray = $this->sortGeoStatArrayBasedOnAttempst($data);
        $countryLabels = array_keys($sortedArray);
        $data_unsetcount = $this->unsetCounts($data);

        $attackTypeArray = array(2,3,4,5,6,7,8,10,11,12,13,14,15);
        foreach($data_unsetcount as $key=>$value)
        {
            if(array_key_exists($key,$sortedArray))
            {
                foreach($attackTypeArray as $attackNo)
                {
                    $result[$attackNo][] = $value['attacktype'][$attackNo];
                }
            }
        }
        $geo_stat['countryLabel'] = $countryLabels;
        $result1 = $this->getAttackNameGeoStats($result);
        $geo_stat['data'] = $result1;
        return $geo_stat;

    }

    public function getAttackNameGeoStats($data)
    {
        $temp = array();
        foreach($data as $key=>$value)
        {
            $attackname = $this->getAttackName($key);
            $attackname = str_replace(' ', '', $attackname);
            $temp[$attackname] =$value;
        }
        return $temp;
    }

    public function sortGeoStatArrayBasedOnAttempst($data)
    {
        $temp =array();
        foreach($data as $key=>$value)
        {
            if(strpos($key,'#') !== false)
            {
                $temp1 = explode('#',$key);
                $temp[$temp1[0]] = $value;
            }
        }
        arsort($temp);
        if(count($temp)>3)
        {
            return array_slice($temp, 0, 3);
        }else {
            return $temp;
        }
    }

    public function unsetCounts($data)
    {
        foreach($data as $key=>$value)
        {
            if(strpos($key,'#') !== false)
            {
                unset($data[$key]);
            }
        }
        return $data;
    }
    public function fillNonExistingAtttacksWithValues($data)
    {
        $result = array();
        $attackArray = array(2,3,4,5,6,7,8,10,11,12,13,14,15);
        foreach($attackArray as $attackNo)
        {
            if(!array_key_exists($attackNo,$data))
            {
                $result[$attackNo] = 0;
            }
        }
        return $result;

    }

    public function prepareAttackTypeArray($countryCode,$attackTypeArray)
    {
        foreach ($attackTypeArray as $attackNo) {
            if (!isset($this->geo_stats[$countryCode]['attacktype'][$attackNo])) {
                $this->geo_stats[$countryCode]['attacktype'][$attackNo] = 1;
            } else {
                $this->geo_stats[$countryCode]['attacktype'][$attackNo] = $this->geo_stats[$countryCode]['attacktype'][$attackNo] + 1;
            }
        }
    }


    /*
     * CODE TO MANAGE WEB LOGS
     */
    public function manageExpiredLogs()
    {
        $expiredLogFiles = $this->prepareLogInfoList();
        if (!empty($expiredLogFiles)) {
            $zippath_temp = $this->prepareZipArchieveLogFiles($expiredLogFiles);
            if($zippath_temp['status']==1)
            {
                $zippath = $zippath_temp['info'];
            }else{
                return $zippath_temp;
            }
            if (file_exists($zippath)) {
                $this->deleteLogFolders($expiredLogFiles);
            }
            return oseFirewallBase::prepareCustomMessage(1, 'The Backup for the weblog has been successfully created');
        } else {
            return oseFirewallBase::prepareCustomMessage(2, 'No need to delete log files');
        }
    }

    //returns the absoulte path for the log files that has expired
    public function prepareLogInfoList()
    {
        $filesList = $this->fwscanner->prepareListOfattackFiles();
        $fileInfoList = array();
        if(!empty($filesList)) {
            foreach ($filesList as $blockedFiles) {
                if (basename($blockedFiles) == 'blocked.php') {
                    $lastAttackDate = $this->getLastAttackDate($blockedFiles);
                    if(empty($lastAttackDate))
                    {
                     return false;
                    }
                    if ($this->isLogExpired($lastAttackDate)) {
                        array_push($fileInfoList, $blockedFiles);
                    }
                }
            }
            return $fileInfoList;
        }else {
            return false;
        }
    }


    //prepares a zip archieve with all the log files that has expired
    public function prepareZipArchieveLogFiles($expiredLogFiles)
    {
        $currentDate = date('d-m-Y his');
        $zipPath = OSE_WEBLOG_BACKUPFOLDER.ODS.'weblogbackup-'.$currentDate.'.zip';
        if(!oseFirewallBase::isSuite())
        {
            if(!file_exists(OSE_WEBLOG_BACKUPFOLDER))
            {
                mkdir(OSE_WEBLOG_BACKUPFOLDER);
            }
        }
        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $zip->open($zipPath, ZipArchive::CREATE);
            foreach ($expiredLogFiles as $key => $file) {
                if (!is_readable($file)) {
                    die ("File: $file not found or inaccessible!");
                }
                $targetFileName = basename(dirname(($file))).'-'.basename($file);
                $zip->addFile(realpath($file), $targetFileName);
            }
            $zip->close();
            return oseFirewallBase::prepareSuccessMessage($zipPath);
        } else {
            //ZIPARCHIEVE DOES NOT EXISTS
            $msg = "ZipArchieve library not found, Please contact your Hosting Company to install the extension ";
            return oseFirewallBase::prepareErrorMessage($msg);
        }
    }

    //delete all the files in the folder along eith the log folder
    public function deleteLogFolders($expiredLogFiles)
    {
        foreach($expiredLogFiles as $blockedFiles)
        {
            array_map('unlink', glob(dirname($blockedFiles)."/*"));
            if(file_exists(dirname($blockedFiles)))
            {
                rmdir(dirname($blockedFiles));
            }
        }
    }

    //return the latest attack date from a blocked file
    public function getLastAttackDate($filepath)
    {
        $content = $this->getBlockedFileContent($filepath);
        if($content !== false){
            $record = end($content);
            if(isset($record['attackdatetime']) && is_array($record['attackdatetime']))
            {
                return $record['attackdatetime'][0];
            }else{
                return $record['attackdatetime'];

            }
        }
    }

    //check if the log file has expired
    public function isLogExpired($lastcheck)
    {
        $formattedDate = $this->getDateTimeFormat($lastcheck);
        $datetime1 = new DateTime();
        $datetime2 = new DateTime($formattedDate);
        $interval = $datetime1->diff($datetime2);
        if($interval->y>=1 || $interval->m>=1 ||$interval->d>=WEBLOGBACkUP_ALLOWED_MONTHS) //change if days >30 days
        {
            return true;
        }else {
            return false;
        }
    }

    //format the date to the formt : y-m-d h:m:s
    public function getDateTimeFormat($lastCheck)
    {
        $date = substr($lastCheck,0,2);
        $month = substr($lastCheck,2,2);
        $year = substr($lastCheck,4,2);
        $hour = substr($lastCheck,6,2);
        $min = substr($lastCheck,8,2);
        $sec = substr($lastCheck,10,2);
        $dateFormat = $year.'-'.$month.'-'.$date.' '.$hour.':'.$min.':'.$sec;
        return $dateFormat;
    }

    //manage the zip backup files of the logs
    //delete them after 3 months
    public function manageWebLogBackups()
    {

        if(file_exists(OSE_WEBLOG_BACKUPFOLDER)) {
            $filesList = scandir(OSE_WEBLOG_BACKUPFOLDER);
            $excludeArray = array('.', '..');
            $filesList = array_diff($filesList, $excludeArray);
            if (!empty($filesList)) {
                foreach ($filesList as $backupZip) {
                    if ((strpos(basename(($backupZip)), 'weblogbackup')) !== false) {
                        $expired = $this->hasZipBackupExpired(basename($backupZip));
                        if ($expired) {
                            if(file_exists(OSE_WEBLOG_BACKUPFOLDER . ODS . $backupZip))
                            {
                                unlink(OSE_WEBLOG_BACKUPFOLDER . ODS . $backupZip);
                            }
                        }
                    }
                }
                return oseFirewallBase::prepareCustomMessage(1, 'WebLog Backup maintenance completed');
            } else {
                return oseFirewallBase::prepareCustomMessage(2, 'There are no backup files ');
            }
        }else{

        }  return oseFirewallBase::prepareCustomMessage(2, 'There are no backup files ');

    }

    public function hasZipBackupExpired($backupZip)
    {
        $temp = explode('weblogbackup-',$backupZip);
        $date = explode('.zip',$temp[1]);
        $formattedDate = $this->formatZipBackupDate($date[0]);
        $datetime1 = new DateTime();
        $datetime2 = new DateTime($formattedDate);
        $interval = $datetime1->diff($datetime2);
        if($interval->y>=1 || $interval->m>=WEBLOGBACkUP_ALLOWED_MONTHS)
        {
            return true;
        }else {
            return false;
        }
    }

    public function formatZipBackupDate($date)
    {
        $temp = explode(' ',$date);
        $finalDate = $temp[0];
        return $finalDate;
    }

    public function housekeepingV7()
    {
        oseFirewall::callLibClass('fwscannerv7','fwscannerv7');
        $fwscannerv7 = new oseFirewallScannerV7();
        $settings = $fwscannerv7->getFirewallSettingsfromDb();
        if($settings['status'] == 1 && $settings['info'][1] == 1) {
            $expiredLogs = $this->manageExpiredLogs();
            if (!empty($expiredLogs) && isset($expiredLogs['status']) && $expiredLogs['status'] == 0) {
                return $expiredLogs;
            }
            $this->manageWebLogBackups();
            oseFirewall::callLibClass('fwscannerv7', 'ipManagement');
            $ipmanagement = new ipManagement(false);
            $ipmanagement->removeExpiredIps();
            oseFirewallBase::callLibClass('fwscannerv7','emailNotificationMgmt');
            $emailMgmt = new emailNotificationMgmt();
            $emailMgmt->maintainEmailNotificationFile();
            $ipmanagement->clearOldIpsData();
            return oseFirewallBase::prepareSuccessMessage("House Keeping completed for v7");
        }else{
            return oseFirewallBase::prepareCustomMessage(4,"Firewall v7 is turned off");
        }
    }







}