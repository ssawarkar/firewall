<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 19/08/2016
 * Time: 9:43 AM
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
oseFirewall::loadJSON ();
class emailNotificationMgmt{
    private $emailNotiicationtable = '#__osefirewall_emailnotificationmgmtv7';
    private $fs = null;
    private $fwstats = null;
    private $receiveEmail = false;
    public function __construct($qatest = false)
    {
        $this->qatest = $qatest;
        $this->db = oseFirewall::getDBO();
        oseFirewallBase::callLibClass('fwscannerv7','fwscannerv7');
		$this->fs= new oseFirewallScannerV7();
    }
    public function loadLibrary()
    {
        oseFirewallBase::callLibClass('fwscannerv7','fwstatsv7');
        $this->fwstats= new fwstatsv7();
    }

    public function getSettings()
    {
        $query = "SELECT `key`, `value` FROM `#__osefirewall_emailnotificationmgmtv7`";
        $this->db->setQuery($query);
        $result1 = $this->db->loadResultList();
        if(!empty($result1)){
            $result['status'] = 1;
            $result['info'] = $result1;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "There was some problem in retrieving the settings ";
            return $result;
        }
    }

    public function getFormattedSettings()
    {
        $query = "SELECT `key`, `value` FROM `#__osefirewall_emailnotificationmgmtv7`";
        $this->db->setQuery($query);
        $result1 = $this->db->loadResultList();
        $range = range(0,10);
        $activesettings = array();
        $i= 0;
        foreach($result1 as $key=>$val)
        {
            if(in_array($key,$range))
            {
                $activesettings[$i]['key'] = $val['key'];
                $activesettings[$i]['value'] = $val['value'];
                $i++;
            }
        }
        if(!empty($activesettings)){
            $result['status'] = 1;
            $result['info'] = $activesettings;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "There was some problem in retrieving the settings ";
            return $result;
        }
    }

    public function saveSettings($data)
    {
        foreach($data as $record)
        {

            $varArray = array(
                'value' =>$record['value'],
            );
            if($record['key'] == 'stats')
            {
                if(!oseFirewallBase::checkSubscriptionStatus(false))
                {
                    $varArray = array(
                        'value' => 0,
                    );
                }
                //check if country databse has been installed
                oseFirewallBase::callLibClass('fwscannerv7','fwstatsv7');
                $fwstats = new fwstatsv7();
                $geodbexists = $fwstats->geoDBExists();
                if($geodbexists == false)
                {
                    $varArray = array(
                        'value' => 0,
                    );
                }
            }
            $result = $this->db->addData('update', '#__osefirewall_emailnotificationmgmtv7', 'key', $record['key'], $varArray);
            $this->db->closeDBO ();
            if($result == 0)
            {
                $temp['status'] = 0;
                $temp['message'] = 'There was some problem in updating the settings for '.$record['key'];
                return $temp;
            }
        }
        //update the cron jobs
        if(oseFirewallBase::checkSubscriptionStatus(false)) {
            $this->saveCronJobSettingsEmailStats();
        }else {
            $return['status'] = 'Success';
            $return['message'] = 'Your email notification preferences have been saved successfully ';
            return $return;
        }
    }

    //to update the settings for cron jobs to send email stats
    public function saveCronJobSettingsEmailStats()
    {
        $statsSettings = $this->getStatsEmailFrequency();
        if($statsSettings == 0)
        {
            $enabled = 0;
        }else {
            //enabled
            $enabled = 1;
        }
        $dateparams = $this->getCronJobDateParameters($statsSettings);
        oseFirewall::callLibClass('panel','panel');
        $panel = new panel();
        //tyoe no =>5;
        //cloudbackuptype = 1
        //gitbackup frequency = null
       $panel->saveCronConfigEmailStats($dateparams['custhours'], $dateparams['custweekdays'], 5, 1, $enabled, null);
    }
    public function getCronJobDateParameters($statsSettings)
    {
        $result = array();
        date_default_timezone_set('Australia/Melbourne');
        $time = date("H.i", time());
        $custhours  =  ceil($time);
        if($statsSettings == 1)
        {
            //daily
            $custweekdays = Array(0,1,2,3,4,5,6);
            $result['custweekdays'] = base64_encode(oseJSON::encode($custweekdays));
            $result['custhours'] =$custhours;
            return $result;
        }else{
            $day = date('D');
            $dayNo = $this->getCustWeekArray(strtolower($day));
            $custweekdays = array($dayNo);
            $result['custweekdays'] = base64_encode(oseJSON::encode($custweekdays));
            $result['custhours'] =$custhours;
            return $result;
        }
    }
    //return apropriate no based on the day
    public function getCustWeekArray($day)
    {
        switch ($day) {
            case 'sun':
                return 0;
                break;
            case 'mon':
                return 1;
                break;
            case 'tue':
                return 2;
                break;
            case 'wed':
                return 3;
                break;
            case 'thu':
                return 4;
                break;
            case 'fri':
                return 5;
                break;
            case 'sat':
                return 6;
                break;
        }
    }

    public function prepareEmailContent($type,$content,$mode)
    {
        if($type == 'googleauth')
        {
            $result = $this->prepareGoogleAuthEmailContents();
            return $result;
        }
        if($type == 'blocked')
        {
            //get blocked mode content
            $result = $this->prepareIPBlockedEmailContent($mode,$content);
            return $result;
        }
        if($type == 'stats') {
            $result = $this->formatEmailStatsContent();
            return $result;
        }
    }


    //prepare an array with all the content for different email types
    //the email content will have the google login secret key and the qr code al;ong with the image
    public function prepareGoogleAuthEmailContents()
    {
            $result = $this->fs->getLoginGAuthKeyandCode();
        if($result['status'] == 1){
        $temp = '<div>Centrora detected that <b> Google 2 Step Authentication</b>is turned on your website</div>
<div style="margin-top: 10px;">Please install the Google Authenticator App from Apple App Store or Google Apps Marketplace to scan this QR Code below, then use the authentication code generated for your login next time.</div>
                <div style="margin-top: 10px; text-align: center">'.$result['qrcode'].'</div>
                <div style="margin-top: 3px; text-align: center; opacity:0.8;">Code generated by this QR will be required to login</div><br/>
                <div>Here is a  <a href = "http://support.google.com/accounts/answer/1066447?hl=en">GUIDE</a> on how to install Google Authenticator if you do not have have the application installed. </div>
                ';
        return $this->prepareCustomeMessage(1,$temp);
        }
        else {
            return $this->prepareCustomeMessage(0,'There was some problem in accessing the QR Code ');
        }
    }
    public function prepareStatsEmailContent()
    {
       $this->loadLibrary();
       $settings= $this->getStatsSettings();
        if(!empty($settings)) {
            $content = array();
            $stats = $this->fwstats->getAttackStatistics();
            if($stats['status'] == 1) {
                if ($settings['timestats'] == 1) {
                    $content['timestats'] = $this->getTimeStats($stats['info']['datestats']);
                }
                if ($settings['attackstats'] == 1) {
                    $content['attackstats'] = $this->getAttackStats($stats['info']['attacktype']);
                }
                if ($settings['ipstats'] == 1) {
                    $content['ipstats'] = $this->getIPStats($stats['info']['geoStats']);
                }
                if ($settings['browserstats'] == 1) {
                    $content['browserstats'] = $this->getbrowserStats($stats['info']['browser']);
                }
                if(!empty($content))
                {
                    return $this->prepareCustomeMessage(1,$content);
                }else {
                    return $this->prepareCustomeMessage(2,'The content is empty ');
                }
            }else {
                //error with gettting the stats
                return $this->prepareCustomeMessage(2,'The content is empty ');
            }
        }else {
            //error with getting the settings
            return $this->prepareCustomeMessage(0,'There was some problem in accessing the settings ');
        }
    }

    public function formatEmailStatsContent()
    {
        $emailContent = null;
        $sendEmail = $this->managerMonthlyAndFortnigthlyEmail();
        if($sendEmail['status'] == 1) {
            $stats = $this->prepareStatsEmailContent();
            if ($stats['status'] == 1) {
                if (!empty($stats['info']['timestats'])) {
                    $content_timestats = '<div> Here are the security statistics for your Website :<br/></div>
                            <h3>Attack statistics : <br/></h3>
                            <div> Total of : <b>' . ($stats['info']['timestats']) . ' Attacks were Detected</b> </div>
                            <br/>';
                    $emailContent .= $content_timestats;
                }
                if (isset($stats['info']['attackstats']) && ($stats['info']['attackstats']['status'] == 1)) {
                    $tablecontent = $this->formatTableContent($stats['info']['attackstats']['info']);
                    $content_attacktype = '
                            <div><h3>Attack Type Statistics</h3></div>
                            <div> Following are the top 5 type of attacks that were detected</div><br>
                           ' . $tablecontent;
                    $emailContent .= $content_attacktype;
                }
                if (isset($stats['info']['ipstats']) && $stats['info']['ipstats']['status'] == 1) {
                    $iptableStatsTable = $this->formatTableContent($stats['info']['ipstats']['info']);
                    $content_ipstats = '
                                    <h3> GEO/IP Statistics</h3>
                                    <div> Following is the distribution of attacks based on the geographical region</div>
                                    ' . $iptableStatsTable;
                    $emailContent .= $content_ipstats;
                }
                if (!empty($stats['info']['browserstats'])) {
                    $content_browserstats = '
                            <h3>Browser Related Statistics</h3>

                            <div>About &nbsp <b>'.$stats['info']['browserstats'][key($stats['info']['browserstats'])].' attackers used '.key($stats['info']['browserstats']).' </b> &nbsp to perform the attack.
                                            ';
                    $emailContent .= $content_browserstats;
                }
                return $this->prepareCustomeMessage(1, $emailContent);
            } else if ($stats['status'] == 2) {
                //if the stats are blank
                $msg = '<div>Your website is secured, No attack(s) has been detected on the website</div>';
                return $this->prepareCustomeMessage(1, $msg);
            } else {
                return $stats;
            }
        }else {
            return $sendEmail;
        }
    }

    //manage cron job based on monthly and fortnigthly subscription
    public function managerMonthlyAndFortnigthlyEmail()
    {
        //check for monthly and fortnightly
        $frequency = $this->getStatsSettings();
        if(!empty($frequency))
        {
            if(isset($frequency['stats_fortnigthly']) && $frequency['stats_fortnigthly'] == 1)
            {
                $result = $this->shouldSendStatsEmail('stats_fortnigthly');
                if($result == true)
                {
                    return $this->prepareCustomeMessage(1,'fortnightly - send email');
                }else {
                    return $this->prepareCustomeMessage(0,'no need to send email -fortnightly');
                }

            }else if(isset($frequency['stats_monthly']) && $frequency['stats_monthly'] == 1)
            {
                $result = $this->shouldSendStatsEmail('stats_monthly');
                if($result == true)
                {
                    return $this->prepareCustomeMessage(1,'monthly - send email');
                }else {
                    return $this->prepareCustomeMessage(0,'no need to send email -monthly');
                }
            }else {
                //daily and weekly
                return $this->prepareCustomeMessage(1,'daily/weekly - send email');
            }
        }else {
            return $this->prepareCustomeMessage(0,'The stats settings are empty');
        }
    }

    public function getCronJobdetails()
    {
        oseFirewall::callLibClass('panel','panel');
        $panel = new panel();
        $result = $panel->getCronJobdetails();
        $decode_result = (json_decode($result));
        return $decode_result;
    }
    protected function getCurrentTime () {
        date_default_timezone_set ( 'Australia/Melbourne' );
        $time = date ( "Y-m-d H:i:s" );
        return $time;
    }

    public function shouldSendStatsEmail($type)
    {
        $currentDateTime = $this->getCurrentTime();
        $cronJobDetails = $this->getCronJobdetails();
        $current = new DateTime($currentDateTime);
        $lastcompleted = new DateTime($cronJobDetails->lastcompleted);

        $interval = $current->diff($lastcompleted);
        $elapsed_month = $interval->format('%m');
        $elapsed_days = $interval->format('%a');
        if(!empty($cronJobDetails)) {
            if ($type == 'stats_fortnigthly') {
                if ($elapsed_days >= 14 || $elapsed_month>0) //336 hours == 14 days
                {
                    return true;
                } else {
                    return false;
                }
            } else if ($type == 'stats_monthly') {
                if ($elapsed_month>0) // after 720 hours = == 30 days
                {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }else {
            return false;
        }
    }
    public function formatTableContent($data)
    {
        $content = '<table style="width:100%; border-collapse: collapse;">';
        foreach($data as $key =>$value)
        {
            $content.='<tr>';
            $content.='<td style=" border: 1px solid grey; padding: 3px 0px 3px 10px;">'.$key.'</td>';
            $content.='<td style=" border: 1px solid grey; padding: 3px 0px 3px 10px;">'.$value.'</td>';
            $content.='</tr>';
        }
        $content.= '</table>';
        return $content;
    }

    public function getStatsSettings()
    {
        $settings = $this->getSettings();
        $range = range(3,10);
        $activesettings = array();
        foreach($settings['info'] as $key=>$val)
        {
            if(in_array($key,$range))
            {
                $activesettings[$val['key']] = $val['value'];
            }
        }
        return ($activesettings);
    }
    //returns the option chosed by the user for the frequency of receiving emails
    public function getStatsEmailFrequency()
    {
        $frequency = null;
        $query = "SELECT `key`, `value` FROM `#__osefirewall_emailnotificationmgmtv7` WHERE `id` BETWEEN 8 AND 11 ";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        if(!empty($result)) {
            foreach ($result as $key => $value) {
                if ($value['value'] == 1) {
                    if ($value['key'] == 'stats_daily') {
                        return 1;
                    } elseif ($value['key'] == 'stats_weekly') {
                        return 2;
                    } else if ($value['key'] == 'stats_fortnigthly') {
                        return 3;
                    }
                    if ($value['key'] == 'stats_monthly') {
                        return 4;
                    }
                }
            }
            return 0;
        }else {
            return 0;
        }
    }

    public function getTimeStats($monthstats)
    {
        $count = array_sum($monthstats['monthstats_values']);
        return $count;
    }
    public function getAttackStats($attackStats)
    {
        $attackTypeStats = array_combine( $attackStats['attacktype_keys'],$attackStats['attacktype_values']);
        arsort($attackTypeStats);
        $attackCount = array_sum($attackTypeStats);
        if($attackCount!=0) {
            $result = array();
            foreach ($attackTypeStats as $key => $val) {
                $result[$key] = $this->calculatePercentage($val, $attackCount);
            }
            return $this->prepareCustomeMessage(1,array_splice($result, 0, 5));
        }else {
            return $this->prepareCustomeMessage(0,'The attacktype stats are blank');
        }
    }

    public function calculatePercentage($value,$total)
    {
        return number_format(($value *100)/$total,2).'%';
    }
    public function getIPStats($ipstats)
    {
        $countryCount = count($ipstats['countryLabel']);
        $result = array();
        $temp = array();
        for($i=0;$i<$countryCount;$i++)
        {
           $array =  array_column($ipstats['data'],$i);
           $sum = array_sum($array);
           $result[$ipstats['countryLabel'][$i]] = $sum;
           $sum = 0;
        }
        $attackCount = array_sum($result);
        if($attackCount !== 0) {
            foreach ($result as $key => $val) {
                oseFirewallBase::callLibClass('CountryBlock','CountryBlock');
                $countryFlag = new CountryBlock();
                $countryName = $countryFlag->getCountryName($key);
                $temp[$countryFlag->getCountryFlagForEMail($key) .' ['.$countryName->country_name.']'] = $this->calculatePercentage($val, $attackCount);
            }
            return $this->prepareCustomeMessage(1,$temp);
        }else {
            return $this->prepareCustomeMessage(0,'No attacks were detected');
        }
    }
    public function getbrowserStats($browserstats)
    {
        $browser_stats =  array_combine($browserstats['browser_keys'],$browserstats['browser_values']);
        arsort($browser_stats);
        $browserCount = array_sum($browser_stats);
        if($browserCount !== 0) {
            $temp = array_splice($browser_stats, 0, 1);
            $result[key($temp)] = $this->calculatePercentage($temp[key($temp)], $browserCount);
            return $result;
        }
        else {
            return $this->prepareCustomeMessage(0,'No attacks were detected');
        }
    }

    public function prepareIPBlockedEmailContent($mode,$content)
    {
        if(empty($content)) {
            return $this->prepareCustomeMessage(0,'The content for the blocked ip is blank');
        }
        else {
            $subscription_status = oseFirewallBase::checkSubscriptionStatus(false);
            if(!$subscription_status)
            {
                $mode = false;
            }
            if ($mode == false) {
                //FILTER MODE
                if(!oseFirewallBase::checkSubscriptionStatus(false))
                {
                    $isNotified = 0;
                }else{
                    $isNotified = $this->isIpNotified($content['ip']);
                }
                if ($isNotified == 1) {
                    //email has been sent for the attack
                    //do nothing
                    $content = $this->prepareCustomeMessage(0, 'The email has already been sent for the attack');
                    return $content;
                } else {
                    //format the content for the email
                    $content_formatted = $this->formatAttackInfoContentEmail($content, $mode);
                    if ($content_formatted == false) {
                        return $this->prepareCustomeMessage(0, 'The content for the blocked ip is blank');
                    } else {
                        //update the notified status in the database with the specific ip
                        if($subscription_status)
                        {
                            $result_dbupdate = $this->updateNotifiedStatusForIp($isNotified, $content_formatted['ip']);
                        }else{
                            $result_dbupdate = 1;
                        }
                        if ($result_dbupdate !== 0) {
                            $formattedContent = $this->formatIpBlockedEmailContent($content_formatted, $mode);
                            return $this->prepareCustomeMessage(1, $formattedContent);
                        } else {
                            return $this->prepareCustomeMessage(0, 'There was some problem in updating the notified value in db for  ' . $content_formatted['ip']);
                        }
                    }
                }
            }
            if ($mode == true) {
                //BLOCK MODE
                $content_formatted = $this->formatAttackInfoContentEmail($content, $mode);
                if (($content_formatted !== false)) {
                    $formattedContent = $this->formatIpBlockedEmailContent($content_formatted, $mode);
                    return $this->prepareCustomeMessage(1, $formattedContent);
                } else {
                    return $this->prepareCustomeMessage(0, 'There some problem in generating the content for the blocked ip' . $content_formatted['ip']);
                }
            }
        }
    }

    public function formatIpBlockedEmailContent($content,$mode)
    {
        if($mode == true)
        {
            $emailContent = '<div><h3>Attack detected : IP has been blocked</h3></div>';

        }else {
            $emailContent = '<div><h3>Attack detected for the first time</h3></div>';
        }
        $emailContent.=  '<div> The followings are the details of the attacks </div>
                          <ul style="line-height: 21px;">
                          <li> IP:&nbsp <b>'.$content['ip'].'</b></li>
                          <li> Browser Used : &nbsp<b>'.$content['browser'].'</b></li>
                          <li> Date & Time : &nbsp<b>'.$content['attackdatetime'].'</b></li>
                          <li> Score : &nbsp<b>'.$content['score'].'</b></li>
                          <li> Attempt(s): &nbsp<b>'.$content['attempt'].'</b></li>
                          </ul>
                          ';
        $attackTypeContent = $this->formatAttackTypeList($content['attckname']);
        $emailContent.= $attackTypeContent;
        return $emailContent;
    }

    public function formatAttackTypeList($attackTypeArray)
    {
        $emailcontent = '<div style="margin-top: 20px;">Following are the type of attacks that were detected: </div><ul class="email-list">';
        foreach($attackTypeArray as $key=>$value)
        {
            $emailcontent.='<li style="float:left; margin-right: 25px;">'.$value.'</li><br/>';
        }
        $emailcontent.='</ul>';
       return $emailcontent;
    }

    public function formatAttackInfoContentEmail($content,$mode)
    {
        $result = array();
        if(!empty($content)) {
            $result['ip'] = $content['ip'];
            if (is_array($content['browser'])) {
                $result['browser'] = $content['browser'][0];
            } else {
                $result['browser'] = $content['browser'];
            }
            if (is_array($content['attackdatetime'])) {
                $result['attackdatetime'] = $this->formateDateTime($content['attackdatetime'][0]);
            } else {
                $result['attackdatetime'] = $this->formateDateTime($content['attackdatetime']);
            }
            $result['score'] = $content['score'];
            $result['attempt'] = $content['attempt'];
            $result['attckname'] = $this->formatAttackName(array_unique($content['attacktype']));
            $result['isblocked'] = $mode;
            return $result;
        }else {
            return false;
        }
    }

    public function updateNotifiedStatusForIp($isNotified,$ip)
    {
        if(empty($ip))
        {
            return 0;
        }
        $temp = $this->updateIpNotificationStatus($ip,1);
        return  $temp;
    }

    public function isIpNotified($ip)
    {
        $content = $this->readFilteredModeNotificationFile();
        if(empty($content))
        {
            return 2 ; //Ip has not beeen notified
        }else{
            if(array_key_exists($ip,$content))
            {
                //get the value form the local file , 0 or 1
              return $content[$ip];
            }else{
                //no record exists
                return 2;
            }
        }

    }

    public function formateDateTime($date)
    {
        $dateno = substr($date, 0, 2);
        $month = substr($date, 2, 2);
        $year= substr($date, 4, 2);
        $hour = substr($date, 6, 2);
        $min = substr($date, 8, 2);
        $sec = substr($date, 10, 2);
        $timestamp = $dateno.'/'.$month.'/'.$year.' '.$hour.':'.$min.':'.$sec;
        return $timestamp;
    }

    public function formatAttackName($attacknameArray)
    {
        oseFirewallBase::callLibClass('fwscannerv7','fwstatsv7');
        $fstats = new fwstatsv7();
        $i = 0;
        $result= array();
        foreach($attacknameArray as $array)
        {
            $result[$i] = $fstats->getAttackName($array);
            $i++;
        }
        return $result;
    }

    public function sendEmail($type,$content,$mode = false)
    {
        $shouldSend = $this->doesUserWantsToReceiveMails($type);
        if($shouldSend == true)
        {
            $receiptient_email = $this->fs->getEmailFromDb();
            if($receiptient_email['status'] == 1)
            {
                oseFirewall::callLibClass('emails', 'emails');
                $oseEmail = new oseFirewallemails ();
                $email['receipientemail'] = $receiptient_email['value'];
                $email['subject'] = $this->getEmailSubject($type,$mode);
                $temp  = $this->prepareEmailContent($type,$content,$mode);
                if($temp['status'] == 0)
                {
                    return $temp;
                }else {
                    $email['body'] =$temp['info'];
                }
                $result = $oseEmail->sendEMailV7($email['body'], $email['subject'], $email['receipientemail']);
                return oseFirewallBase::prepareSuccessMessage("Stats Email sent");
            }else {
                $result['status'] = 0;
                $result['info'] = 'The user email address has not been set';
                return $result;
            }
        }else {
            $result['status'] = 0;
            $result['info'] = 'The user does not wants to receive email related to '.$type;
            return $result;
        }
    }

    public function loadEmailTemplate()
    {
        $body = file_get_contents(dirname(__DIR__) . ODS . 'emails' . ODS . 'emailv7.tpl');
        return $body;
    }

    public function formateTemplate($template,$subject,$body)
    {
        $template = str_replace('{name}', 'Administrator', $template);
        $template = str_replace('{header}', $subject, $template);
        $template =  str_replace('{content}', $body, $template);
        return $template;
    }

    //check if the use has chosen to receive email related  to this
    public function doesUserWantsToReceiveMails($type)
    {
        $settings = $this->getSettings();
        if($settings['status'] == 1)
        {
            if($type == 'blocked')
            {
                if($settings['info'][0]['key'] == 'blocked_ip' && $settings['info'][0]['value'] == 1)
                {
                    return true;
                }else {
                    return false;

                }
            }
            elseif($type == 'googleauth')
            {
                if($settings['info'][1]['key'] == 'googleauth' && $settings['info'][1]['value'] == 1)
                {
                    return true;
                }else {
                    return false;

                }
            }
            elseif($type == 'stats')
            {
                if($settings['info'][2]['key'] == 'stats' && $settings['info'][2]['value'] == 1)
                {
                    return true;
                }else {
                    return false;

                }
            }else {
                return $this->prepareCustomeMessage(0,'Wrong label for the email type ');
            }
        }else {
            return false;
        }
    }

    public function getEmailSubject($type,$mode)
    {
        $subject = false;
        if($type == 'blocked' && $mode == true)
        {
            $subject = 'IP has been blocked'. " for [" . $_SERVER['HTTP_HOST'] . "]";
        }else  if($type == 'blocked' && $mode == false)
        {
            $subject = 'An Attack has been detected'. " for [" . $_SERVER['HTTP_HOST'] . "]";
        }else if($type == 'googleauth')
        {

            $subject = 'Copy of Google Authentication Login Code'. " for [" . $_SERVER['HTTP_HOST'] . "]";
        }else if($type == 'stats')
        {
            $subject = 'Website Security Statistics'. " for [" . $_SERVER['HTTP_HOST'] . "]";
        }
        return $subject;
    }


    public function prepareCustomeMessage($status , $message)
    {
        $result['status'] = $status;
        $result['info'] = $message;
        return $result;
    }



    /*
     * Code to update the ip status for the filter mode
     */
    public function readFilteredModeNotificationFile()
    {
        $emailNotification = array();
        if(file_exists(OSE_FILTER_EMAIL_NOTIFI)) {
            require(OSE_FILTER_EMAIL_NOTIFI);
        }
        return $emailNotification;
    }

    public function writeFilteredModeNotificationContents($content)
    {
        $filecontent = "<?php\n" . '$emailNotification = ' . var_export($content, true) . ";";
        if(file_exists(OSE_FILTER_EMAIL_NOTIFI))
        {
            $flag_email = true;
        }else{
            $flag_email = false;
        }
        $result = file_put_contents(OSE_FILTER_EMAIL_NOTIFI, $filecontent);
        if(!$flag_email)
        {
            chmod(OSE_FILTER_EMAIL_NOTIFI,0777);
        }
        return ($result == false) ? false : true;
    }

    public function updateIpNotificationStatus($ip,$status)
    {
        $old_content = $this->readFilteredModeNotificationFile();
        if(empty($old_content))
        {
            $new_content = array("$ip"=>$status);
           $temp =  $this->writeFilteredModeNotificationContents($new_content);
        }else{
            $old_content[$ip]= $status;
            $temp = $this->writeFilteredModeNotificationContents($old_content);
        }
        return $temp;
    }

    public function deleteNotificationFile()
    {
        if(file_exists(OSE_FILTER_EMAIL_NOTIFI)) {
            unlink(OSE_FILTER_EMAIL_NOTIFI);
        }
    }

    public function removeIpsFromEmailNotification($iparray)
    {
        if(empty($iparray) || !is_array($iparray))
        {
            return oseFirewallBase::prepareSuccessMessage("Ip array is empty ");
        }else{
            $old_content = $this->readFilteredModeNotificationFile();
            foreach($old_content as $key=>$value)
            {
                if(in_array($key,$iparray))
                {
                    unset($old_content[$key]);
                }
            }
            $temp = $this->writeFilteredModeNotificationContents($old_content);
            if($temp)
            {
                return oseFirewallBase::prepareSuccessMessage("EmailNotification file has been updated ");

            }else{
                return oseFirewallBase::prepareErrorMessage("There was some problem in updating EmailNotification file");

            }
        }

    }

    public function maintainEmailNotificationFile()
    {
        oseFirewall::callLibClass('fwscannerv7','ipManagement');
        $ipmanagement = new ipManagement(false);
        $temp_ips = $ipmanagement->getAllIpRecordsFromDb();
        if(empty($temp_ips))
        {
            return true;
        }else {
            foreach ($temp_ips as $record) {
                if (isset($record['ip'])) {
                    $formattedIpArray[] = $record['ip'];
                }
            }
            if(empty($formattedIpArray))
            {
                return true;
            }else{
                $fileContents = $this->readFilteredModeNotificationFile();
                if(!empty($fileContents))
                {
                    foreach($fileContents as $key=>$val)
                    {
                        if(!in_array($key,$formattedIpArray))
                        {
                            unset($fileContents[$key]);
                        }
                    }
                    $this->writeFilteredModeNotificationContents($fileContents);
                }
                return true;
            }
        }
    }




}