<?php
/**
 * @version     2.0 +
 * @package       Open Source Excellence Security Suite
 * @subpackage    Centrora Security Firewall
 * @subpackage    Open Source Excellence WordPress Firewall
 * @author        Open Source Excellence {@link http://www.opensource-excellence.com}
 * @author        Created on 01-Jun-2013
 * @license GNU/GPL http://www.gnu.org/copyleft/gpl.html
 *
 */
if (!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
//ini_set('memory_limit', '-1');
oseFirewall::callLibClass ( 'fwscanner', 'fwscannerbs' );
oseFirewall::loadJSON ();
define('DEFUALT_FIREWALL_SENSITIVITY', 40);
define('DEFAULT_ATTEMPT_THRESHOLD',10); //10
define('ATTEMPT_THRESHOLD', 3);  //attempst thresholds for the brute force protection
define('ATTEMPT_TIMEFRAME', 3); // the time frame that needs to be considered for brute force protection
define('DEFAULT_CONTACT_ADDRESS', 'contact@centrora.com'); // the time frame that needs to be considered for brute force protection
define('MAX_ATTEMP',10); //SET THE MAX ATTEMPT FOR CRITICAL ATTACKS
define('MAX_SCORE',100);//set masx attemps for criticial attacks
class oseFirewallScannerV7
{
    private $ip = null;
    private $url = array();
    private $referer = array();
    private $useragent = array();
    private $datetime = array();
    private $browser = array();
    private $attacktype = array();
    private $statsfileslist = array();
    private $finallist = array();
    private $warningtext = array();
    private $originalrequest_log = array();
    private $date = array();
    private $month = array();
    private $year = array();
    private $hour = array();
    private $fsscannerv7_config_table = '#__osefirewall_fwscannerv7Config';
    private $completerequest = array();
    private $ipmanagement = null;
    private $whitelistmgmt = null;
    private $spamcheckTable = '#__osefirewall_spamcheck';
    private $type = null;
    public $detected_pentest = false;
    public $original_request = array();
    public $patternId = array();
    public $permission = false;

    //stats file variables
    private $yearstats = array();
    private $monthsstats = array();
    private $datesstats = array();
    private $hoursstats = array();
    private $ipstats = array();
    private $browserstats = array();
    private $uastats = array();
    private $attacktypestats = array();
    private $attackstats = array();
    private $allowExts = array();
    protected $replaced = array();
    protected  $detected_whitelistedVars = array();
    protected  $orignal_request_backup = array();

    //run shell commands
    private $workingDirectoryRoot = OSE_DEFAULT_SCANPATH;
    private $gitProcessTimeout = null;

    //anti spamming
    protected $sfs_confidence = 30;
    private $ip32 = null;


    public function __construct($qatest = false)
    {
        $this->qatest = $qatest;
        $this->db = oseFirewall::getDBO();
        $this->prerequisistes();
    }


    //files and databases that needs to be created before the scanning process can be started
    public function prerequisistes()
    {
        $this->accessIp();  //set the value of ip TODO
        $fsscannerv7_configexists = $this->db->isTableExists($this->fsscannerv7_config_table);
        if (!$fsscannerv7_configexists) {
            //if the ip table does not exist
            oseFirewallBase::initialiseFwscannerV7Settings($this->db);
        }
    }

    public function checkPermissions()
    {
        if(oseFirewallBase::isSuite()) {
            $permissions = substr(sprintf('%o', fileperms(OSE_CONTENTFOLDER)), -3);
            $user = substr($permissions, 0, 1);
            $group = substr($permissions, 1, 1);
            $other = substr($permissions, 2, 1);
            $msg = "mkdir " . OSE_WEBLOGFOLDER . "; mkdir " . OSE_WEBLOG_BACKUPFOLDER . "; chmod -R 0777 " . OSE_WEBLOGFOLDER . "<br/>; chmod -R 0777 " . OSE_WEBLOG_BACKUPFOLDER;
            if (($user == 7) && ($group >= 5) && ($other >= 5)) {
                $this->permission = true;
                $this->makeDirectories();
                if (file_exists(OSE_WEBLOG_BACKUPFOLDER) && file_exists(OSE_WEBLOGFOLDER) && $this->checkWebLogBackupFolderPermission() && $this->checkWebLogFolderPermission()) {
                    return $this->prepareSuccessMessage('The folder has appropriate folder permissions');
                } else {
                    return oseFirewallBase::prepareErrorMessage("The folders do not appropriate permissions, please run the following commands : <br/>" . $msg);
                }
            } else {
                $change_perm = chmod(OSE_CONTENTFOLDER, 0755);
                if ($change_perm == true) {
                    $this->permission = true;
                    $this->makeDirectories();
                    if (file_exists(OSE_WEBLOG_BACKUPFOLDER) && file_exists(OSE_WEBLOGFOLDER) && $this->checkWebLogBackupFolderPermission() && $this->checkWebLogFolderPermission()) {
                        return $this->prepareSuccessMessage('The folder has appropriate folder permissions');
                    } else {
                        return oseFirewallBase::prepareErrorMessage("The folders do not appropriate permissions, please run the following commands : <br/>" . $msg);
                    }
                } else {
                    $this->permission = false;
                    $msg = "mkdir " . OSE_CONTENTFOLDER . "; chmod 0755 " . OSE_CONTENTFOLDER . "<br/> ; mkdir " . OSE_WEBLOGFOLDER . "; mkdir " . OSE_WEBLOG_BACKUPFOLDER . "; chmod -R 0777 " . OSE_WEBLOGFOLDER . "<br/>; chmod -R 0777 " . OSE_WEBLOG_BACKUPFOLDER;
                    return oseFirewallBase::prepareErrorMessage("The folders do not appropriate permissions, please run the following commands : <br/>" . $msg);
                }
            }
        }else{
            return $this->prepareSuccessMessage('The folder has appropriate folder permissions');
        }
    }

    public function checkWebLogBackupFolderPermission()
    {
        if(file_exists(OSE_WEBLOGFOLDER))
        {
            $weblogbackup_permisssion =  substr(sprintf('%o', fileperms(OSE_WEBLOGFOLDER)), -3);
            $userbackup_weblog = substr($weblogbackup_permisssion,0,1);
            $groupbackup_weblog = substr($weblogbackup_permisssion,1,1);
            $otherbackup_weblog = substr($weblogbackup_permisssion,2,1);
            if(($userbackup_weblog == 7) && ($groupbackup_weblog==7) && ($otherbackup_weblog==7))
            {
                return true;
            }else{
                return false;
            }
        }else{
            return false;
        }
    }
    public function checkWebLogFolderPermission()
    {
        if(file_exists(OSE_WEBLOG_BACKUPFOLDER))
        {
            $weblog_permisssion =  substr(sprintf('%o', fileperms(OSE_WEBLOG_BACKUPFOLDER)), -3);
            $user_weblog = substr($weblog_permisssion,0,1);
            $group_weblog = substr($weblog_permisssion,1,1);
            $other_weblog = substr($weblog_permisssion,2,1);
            if(($user_weblog == 7) && ($group_weblog==7) && ($other_weblog==7))
            {
                return true;
            }else{
                return false;
            }
        }else{
            return false;
        }
    }

    public function makeDirectories()
    {
        if($this->permission == true)
        {
            if (!file_exists(CENTRORABACKUP_FOLDER)) {
                $this->makeDirs(CENTRORABACKUP_FOLDER,0755);
            }
            if (!file_exists(OSE_WEBLOG_BACKUPFOLDER)) {
                $this->makeDirs(OSE_WEBLOG_BACKUPFOLDER,0777,true);
            }
            if (!file_exists(OSE_WEBLOGFOLDER)) {
                $this->makeDirs(OSE_WEBLOGFOLDER,0777,true);
            }
        }
    }

    private function makeDirs($folderPath, $permission=0755,$rec=false)
    {
        $old_umask = umask(0);
        mkdir($folderPath, $permission,$rec);
        umask($old_umask);
    }

    public function getIp()
    {
        return $this->ip;
    }

    public function loadLibrary()
    {
        oseFirewall::callLibClass('fwscannerv7','ipManagement');
        $this->ipmanagement = new ipManagement(); //will generate the tables if they do not exist
        oseFirewall::callLibClass('fwscannerv7','whitelistmgmt');
        $this->whitelistmgmt = new whitelistmgmt(); // will generate the tables if they do not exist
    }
    //sets the value of ip
    public function accessIp()
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $this->ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $this->ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $this->ip = $_SERVER['REMOTE_ADDR'];
        }
    }

    public function getSeoConfiguration()
    {
        $result  = array();
        $query = "SELECT `id`,`value` FROM `#__osefirewall_fwscannerv7Config` WHERE `type` = 'seo'";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        if(!empty($temp))
        {
            foreach($temp as $record)
            {
                $settings[$record['id']] = $record['value'];
            }
        }
        if(!empty($settings))
        {
            $result['status'] = 1;
            $result['info'] = $settings;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "There was some problem in accessing the settings from the database";
            return $result;
        }
    }

    private function getIdBasedonKeySEO($key)
    {
        switch ($key)
        {
            case '1':
                return "<a href='javascript:void(0);' title = 'WhiteList' onClick= '#'><i class='text-success glyphicon glyphicon-ok-sign' title = 'This IP is currently whitelisted'></i></a>";
                break;
            case '0':
                return "<a href='javascript:void(0);' title = 'monitor' onClick= '#' ><i class='text-yellow glyphicon glyphicon-eye-open' title = 'This IP is actively monitored'></i></a>";
                break;
            case '2':
                return "<a href='javascript:void(0);' title = 'Blacklist' onClick= '#' ><i class='text-block glyphicon glyphicon-minus-sign' title = 'This IP is blacklisted'></i></a>";
                break;
            default:
                return '';
                break;
        }
    }


    public function saveSettings($array,$type)
    {
        $acceptedKeys = array();
        $result = 0;
        if($type== 'general')
        {
            $acceptedKeys = range(1,17);
            array_push($acceptedKeys,25);
            array_push($acceptedKeys,26);
            array_push($acceptedKeys,27);
            array_push($acceptedKeys,33);
        }
        if($type== 'seo')
        {
            $acceptedKeys = range(18,24);
        }
        $validate = $this->validateInput($array);
        if($validate['status'] == 1 )
        {
            foreach($array as $key=>$value)
            {
               if(in_array($key,$acceptedKeys)) {
                   //toogle fws v6
                   if($key == 1 && $value == 1) { //turn off v6 if v7 is turned on
                       oseFirewall::callLibClass('fwscanner', 'fwscanner');
                       $fs = new oseFirewallScanner();
                       $result_temp = $fs->toggleFirewallScanerV6(1);
                       if ($result_temp['status'] == 0) {
                           return $result_temp;
                       }
                       $this->toggleManageWebLogCronJobs(1);
                   }
                   if($key == 1 && $value == 0)
                   {
                       $this->toggleManageWebLogCronJobs(0);
                   }
                       if ($key == 27) {
                           if(isset($array[15]) && $array[15] ==0)
                           {
                               $value = 0;
                           }
                           if (!oseFirewallBase::isSuite()) {
                           if (OSE_CMS == 'joomla') {
                               $temp = $this->updateGoogleAuthLoginJoomla($value);
                               if ($temp == 0) {
                                   $return = $this->prepareErrorMessage("There was some problem in updating the Login Google Authentication in the Joomla Plgin Table");
                                   return $return;
                               }
                           }
                           if (OSE_CMS == 'wordpress') {
                               $temp = $this->toggleGoogleAuthLoginFromProfile($value);
                               if ($temp == 0) {
                                   $return = $this->prepareErrorMessage("There was some problem in updating the Login Google Authentication in the Wordpress usermeta Table");
                                   return $return;
                               }
                           }
                           $fwscannerv7 = new oseFirewallScannerV7();
                           $oldSettings = $fwscannerv7->getFirewallSettingsfromDb();
                           $sendemail = false;
                           if ($oldSettings['status'] == 1 && $oldSettings['info'][27] == 0) {
                               $sendemail = true;
                           }
                           if ($value == 1 && $sendemail) {
                               $this->sendEmailNotification('googleauth', null, false);
                           }
                       }else{
                               //disbale bf google auth for the suite users
                               $value=0;
                           }
                   }
                   if(($key == 28 || $key ==29) && oseFirewallBase::isSuite())
                   {
                       //disable the 2 step authentication for ban page for the suite users
                       $value = 0;
                   }
                    if($key == 29)
                    {
                        die($value);
                    }
                   $result = $this->updateSettings($key, $value);
                   if ($result == 0) {
                       $return = $this->prepareErrorMessage("There was some problem in updating the id:" . $key . " with value" . $value);
                       return $return;
                   }
               }
            }
            if($result == 0)
            {
                return $this->prepareErrorMessage("There was some problem in updating the settings ");
            }else {
                //db was updted successfully
                if($type == "seo")
                {
                    $resullt_updatefile['status'] = 1;
                }else{
                    $resullt_updatefile = $this->updateLocalFiles($array);
                }
                if($resullt_updatefile['status'] == 1 )
                {
                    //the local rules files were updated successfully
                    return $this->prepareSuccessMessage("The settings have been updated successfully ");
                }else
                {
                    //error in updating the local files
                 return $resullt_updatefile;
                }
            }
        }else {
            return $validate;
        }

    }

    public function updateGoogleAuthLoginJoomla($status)
    {
        $Array = array(
            'enabled' => $status,
        );
        $id = $this->db->addData('update', '#__extensions', 'name', 'plg_twofactorauth_totp', $Array);
        return $id;
    }

    public function toggleLoginGoogleAuthentication($value)
    {
        $email_msg = null;
        $email = $this->getEmailFromDb();
        if($email['status'] == 1)
        {
            if(($email['value'] == 'Please enter your email address'))
            {
                return $this->prepareErrorMessage('Please enter a valid email address <br/>An email will be sent to the address with the Google Authentication QR Code');
            }
        }else {
            return $this->prepareErrorMessage('There was some problem in turning Google Authentication: ON');
        }
        if(OSE_CMS == 'joomla')
        {
            $temp =  $this->updateGoogleAuthLoginJoomla($value);
            if($temp == 0)
            {
                $return = $this->prepareErrorMessage("There was some problem in updating the Login Google Authentication in the Joomla Plgin Table");
                return $return;
            }
        }else {
            //wordpress update the usermeta table
            $temp = $this->toggleGoogleAuthLoginFromProfile($value);
            if($temp == 0)
            {
                $return = $this->prepareErrorMessage("There was some problem in updating the Login Google Authentication in the Wordpress Plugin Table");
                return $return;
            }
        }
        if($value == 1)
        {
            $result =  $this->updateSettings(27,1);
        }else {
            $result = $this->updateSettings(27,0);
        }
        if ($result == 0) {
            $return = $this->prepareErrorMessage("There was some problem in updating the Login Google Authentication ");
            return $return;
        }else {
            if($value == 1)
            {
                $email_result = $this->sendEmailNotification('googleauth',null,false);
                if($email_result == 1)
                {
                    $email_msg = "<br/>For your reference a copy of the QR Code has been sent to  ".$email['value'];
                }
                else if($email_result['status'] == 0 || $email_result == 0)
                {
                    $email_msg = '';
                }
            }
            if(OSE_CMS == 'wordpress')
            {   $return['status'] = 1;
                $return['url'] = 'profile.php';
                $return['message'] = 'In the <b>"Google Authenticator Settings" </b>

                                      <ol type="1">
                                      <li> Please click on the <b>ACTIVE </b>checkbox </li>
                                      <li> Scan the QR code using google Authenticator App on you Mobile</li>
                                      <li> Click on the Update Profile</li>
                                      </ol>'.$email_msg;
            }else {
                $user = JFactory::getUser();
                $return['status'] = 1;
                $return['url'] = 'index.php?option=com_users&view=user&layout=edit&id='.$user->id;
                $return['message']= 'In the "Two Factor Authentication Tab" Please Complete the Settings <br/>'.$email_msg;
            }
            return $return;
        }
    }

    public function toggleGoogleAuthLoginFromProfile($value)
    {
        if($value == 1)
        {
            $set_Value = 'enabled';
        }else {
            $set_Value = 'disabled';
        }

        //update
        $varArray = array(
            'meta_value' => $set_Value,
        );
        $id = $this->db->addData('update', '#__usermeta', 'meta_key', 'googleauthenticator_enabled', $varArray);

        return $id;
    }

    //update the local files based on the chnages in the database
    public function updateLocalFiles($array)
    {
        // get the list of rules that has been activated buy the user
        $activeRules = $this->getActiveSettings($array);
        //prepare the rules file based on the active settings
        $result = $this->prepareRulesFile($activeRules);
        if(!$result)
        {
            return $this->prepareErrorMessage("There was a problem in updating the rules file");
        }
        return $this->prepareSuccessMessage("The local file has been updated successfully");
    }

    public function getActiveSettings($array)
    {
        $activeRules = array();
        foreach($array as $key=>$value)
        {
            if(!empty($value))
            {
                //do not conside 1,7 9 as the values are for user information
                //do not consider ids from 12 to 17 as they are used for diffrent attacks
                if(!in_array($key,array(1,7,9,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33)))
                {
                    array_push($activeRules,$key);
                }
            }
        }
        return $activeRules;
    }

    public function validateInput($array)
    {
        foreach($array as $key=>$value)
        {
            if(!empty($value))
            {
                if($key !== 7)  //do not check email address
                {
                    if(strlen($value) < 100) {
                        if (!preg_match('/^[a-z0-9 .\-]+$/i', $value)) {
                            //if malicious content is dounf in the user input
                            $return = $this->prepareErrorMessage("Invalid input: " . $value . " Only Alpha Numeric Characters are allowed with spaces and hypens");
                            return $return;
                        }
                    }else {
                        //length is more than 100
                        return $this->prepareErrorMessage("The message is too long, please enter a message less than 100 characters");
                    }
                }
            }

        }
        return $this->prepareSuccessMessage("The input is validated successfully");
    }

    public function updateSettings($id,$value)
    {
        if(oseFirewallBase::isSuite())
        {
            if(in_array($id,array(27,28,29,34)))
            {
                $value = 0;
            }
        }
            $vararray = array(
                'value' => $value,
            );
            $result = $this->db->addData('update', '#__osefirewall_fwscannerv7Config', 'id', $id, $vararray);
            $this->db->closeDBO();
            return $result;
    }

    public function insertSettings($id,$value)
    {
         if(OSE_CMS == "joomla") {
             $vararray = array(
                 'id' => $id,
                 "key" => "secureKey",
                 'value' => $value,
                 "type" => "bruteforce"
             );
             $result = $this->db->addData('insert', '#__osefirewall_fwscannerv7Config', '', '', $vararray);
             $this->db->closeDBO();
             return $result;
         }else{
             return true;
         }
    }

    public function getFirewallSettingsfromDb()
    {
        $settings  = array();
        $query = "SELECT `id`,`value` FROM `#__osefirewall_fwscannerv7Config` WHERE 1";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        if(!empty($temp))
        {
            foreach($temp as $record)
            {

                $settings[$record['id']] = $record['value'];
                if($record['id'] == 17) // send values till 17 only
                {
                    break;
                }
            }
            $settings[25] = $temp[24]['value']; ////brute force attempts
            $settings[26] = $temp[25]['value']; //brute force time lime
            $settings[27] = $temp[26]['value']; //google authentication for the login page
            if(isset($temp[32]['value']))
            {
                $settings[33] = $temp[32]['value'];//attempt threshold
            }
        }
        if(!empty($settings))
        {
            $result['status'] = 1;
            $result['info'] = $settings;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "The firewall scanner has not been set yet";
            return $result;
        }
    }

    public function getBackendSecureKey()
    {
        $query = "SELECT `value` FROM `#__osefirewall_fwscannerv7Config` WHERE `key`= 'secureKey'";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        if(!empty($temp) && isset($temp[0]['value']))
        {
            return $temp[0]['value'];
        }else{
            return false;
        }

    }

    public function getCompleteFirewallSettingsFromDb()
    {
        $settings  = array();
        $query = "SELECT `id`,`value` FROM `#__osefirewall_fwscannerv7Config` WHERE 1";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        if(!empty($temp))
        {
            foreach($temp as $record)
            {
                $settings[$record['id']] = $record['value'];
            }
        }
        if(!empty($settings))
        {
            $result['status'] = 1;
            $result['info'] = $settings;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "The firewall scanner has not been set yet";
            return $result;
        }
    }

    public function getEmailFromDb()
    {
        $query = "SELECT `value` FROM `#__osefirewall_fwscannerv7Config` WHERE `id`= 7";
        $this->db->setQuery($query);
        $result = $this->db->loadResult();
        if(!empty($result['value']))
        {
            $temp['status'] = 1 ;
            $temp['value'] =  $result['value'];
            return $temp;
        }else {
            $temp['status'] = 0 ;
            $temp['value'] =  "email is blank";
            return $temp;
        }
    }

    //get the firewall settings
    public function getFirewallSettings()
    {
        $fsscannerv7_config_table = '#__osefirewall_fwscannerv7Config';
        $fsscannerv7_configexists = $this->db->isTableExists($fsscannerv7_config_table);
        if($fsscannerv7_configexists)
        {
            $result = $this->prepareSuccessMessage("The table exists ");
            $result['settings'] = $this->getFirewallScannerSettingsFromDb();
            return $result;
        }
        return $this->prepareErrorMessage("The table fwscannerv7Config does not exists ");
    }

    public function getFirewallScannerSettingsFromDb()
    {
        $query = "SELECT * FROM `#__osefirewall_fwscannerv7Config`";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }

    //RULES FILE PREPARATION : get the advanced rules from the database
    public function getAdvanceRulesfromDB()
    {
        $db = oseFirewall::getDBO();
        $query = 'SELECT * FROM `#__osefirewall_advancerules` ';
        $db->setQuery($query);
        $result = $db->loadResultList();
        return $result;
    }

    //RULES FILE PREPARATION : convert the rules into appropriate format
    public function rulesConvertLocalFile($results)
    {
        $i = 0;
        $convertedarray = array();
        foreach ($results as $result) {
            $convertedarray[$i]['id'] = $result['id'];
            $convertedarray[$i]['filter'] = $result['filter'];
            $convertedarray[$i]['action'] = $result['action'];
            $convertedarray[$i]['attacktype'] = $this->getAttackTypeArray($result['attacktype']);
            $convertedarray[$i]['impact'] = $result['impact'];
            $convertedarray[$i]['description'] = $result['description'];
            $i++;
        }
        return $convertedarray;
    }

    //RULES FILE PREPARATION: split the attck type array to make it easier to access
    public function getAttackTypeArray($value)
    {
        $pattern = "/([(].*?[)])|(\w)+/";
        preg_match_all($pattern, $value, $matches);
        return ($matches[0]);
    }

    //RULES FILE PREPARATION:  writes the converted rules in to the local file
    public function writeRulesInTempFile($content)
    {
        $contenttoput = "<?php\n" . '$rules = ' . var_export($content, true) . ";";
        $result = file_put_contents(OSE_ADVANCEDRULES_TEMPFILE, $contenttoput);
        return ($result == false) ? false : true;
    }

    //RULES FILE PREPARATION: function to get the list of all the advanced rules from the temporary local file
    public function getTempRulesfromLocalFile()
    {
        $rules = array();
        if (file_exists(OSE_ADVANCEDRULES_TEMPFILE)) {
            require(OSE_ADVANCEDRULES_TEMPFILE);
        }
        return $rules;
    }

    //RULES FILE PREPARATION : PREPARE THE TEMP RULES FILE
    public function prepareTempRules()
    {
        $listfromdb = $this->getAdvanceRulesfromDB();
        $convertedrules = $this->rulesConvertLocalFile($listfromdb);
        $result = $this->writeRulesInTempFile($convertedrules);
        return $result;
    }

    //MAIN FUNCTION : GETS THE LIST OF RULES BASED ON THE USER SELECTION AND WRITES THEM IN A FILE
    public function prepareRulesFile($rulesarray)
    {
        $temp = true;
        if(!file_exists(OSE_ADVANCEDRULES_RULESFILE))
        {
            $temp = $this->prepareTempRules();
        }
        if(file_exists(OSE_ADVANCEDRULES_RULESFILE))
        {
            $rules = $this->getListofRules();
            if(empty($rules))
            {
                $temp = $this->prepareTempRules();
            }
        }
        if ($temp) {
            //set no 7 and 9 to be null always => used for difrrent fields
            $list = $this->prepareListOfRules($rulesarray);
            $result = $this->generateRuleLocalFile($list);
            return $result;
        } else {
            //error with preparing the local copy of the rules
            return false;
        }
    }

    //generate the file in the centrorabackup folder which store  the rules selected by users
    public function generateRuleLocalFile($rules)
    {
        $contenttoput = "<?php\n" . '$rules = ' . var_export($rules, true) . ";";
        $result = file_put_contents(OSE_ADVANCEDRULES_RULESFILE, $contenttoput);
        if(file_exists(OSE_ADVANCEDRULES_RULESFILE))
        {
            return true;
        }else{
            return false;
        }
    }

    //gets all  the list of rules based on the selction of the users
    public function prepareListOfRules($rulesaray)
    {
        $rules = array();
        $temp = $this->getTempRulesfromLocalFile();
        foreach ($temp as $value) {
            if (array_intersect($rulesaray, $value['attacktype'])) {
                array_push($rules, $value);
            }
        }
        return $rules;
    }

    //get the list of user selected attacks from the local file
    public function getListofRules()
    {
        $rules = array();
        if (file_exists(OSE_ADVANCEDRULES_RULESFILE)) {
            require(OSE_ADVANCEDRULES_RULESFILE);
        }
        return $rules;
    }

    //iterates through the array  of the requests
    public function fwscannerv7($settings,$type)
    {
        $this->loadLibrary();
        $subscription_status = oseFirewallBase::checkSubscriptionStatus(false);
        $this->type = $type;
        $request = $this->getRequestVariables($type);
        $this->original_request = $request; //store the value of original request
        $this->detected_pentest = false;
        $this->orignal_request_backup = $request;
        if(is_array($request) && !empty($request))
        {
            //remove white listed vars
            $request_variablesfiltered = $this->removeWhiteListVariable($request,$type);
            $flatarray = $this->array_flatten($request_variablesfiltered);
            $request_stringsfiltered = $this->hasWhiteListString();
            if(array_key_exists('accountpath',$flatarray))
            {
             $request_stringsfiltered = true;
            }
            if(!$request_stringsfiltered)
            {
               //does not have any white list string
               unset($request_variablesfiltered);
               $request_variablesfiltered = $flatarray;
               if(!empty($request_variablesfiltered))
               {
                   //scan the variables
                   $result = array();
                   $request_variablesfiltered_decoded = $this->codeArray($request_variablesfiltered,'decode');
                   foreach($request_variablesfiltered_decoded as $key=> $rec)
                   {

                       $record[$key] = $rec;
                       $result = $this->scanRequests($record,$request_variablesfiltered_decoded,$settings);  //$request_stringsfiltered
                       unset($record);
                       if($result['status'] == 6)
                       {
                           //if the ip has been blocked
                           if($subscription_status == true) {
                               $this->showBanPage();
                           }
//                           return true;
                       }elseif($result['status'] == 4)
                       {
                           //pattern file not found
                           //do not scan the request
                           $this->errorLog('scannning request',$result['info']);
                           return true;
                       }
                       else
                       {
                           //error or non malicious request
                           if($result['status'] == 0)
                           {
                               $this->errorLog('scanning request',$result['info']);
                           }
                           $subscription_status = oseFirewall::checkSubscriptionStatus(false);
                           if($subscription_status == false)
                           {
                               //free users
//                               $temp  = $this->getCompleteRequest();
//                               $completereq = $this->getTheOriginalArrayStrucutre($request_variablesfiltered);
                               if($this->detected_pentest== false)
                               {
                                   $temp_completereq = $this->getTheOriginalArrayStrucutre($request_variablesfiltered);
                                   $completereq = $this->addWhiteListedVarsBack($temp_completereq);
                                   $this->setRequestVariables($completereq,$type);
                               }
                               else {
                                   $temp_completereq = $this->getTheOriginalArrayStrucutre($request_variablesfiltered_decoded);
                                   $completereq = $this->addWhiteListedVarsBack($temp_completereq);
                                   $this->setRequestVariables($completereq,$type);
                               }

                           }
                           else
                           {
                               //PREMIUM USERS
                               $temp  = $this->getCompleteRequest();
                               if($this->detected_pentest == false)
                               {
                                   $temp_completereq = $this->getTheOriginalArrayStrucutre($request_variablesfiltered);
                                   $completereq = $this->addWhiteListedVarsBack($temp_completereq);
                                   $this->setRequestVariables($completereq,$type);
                               }else {
                                   $temp_completereq = $this->getTheOriginalArrayStrucutre($temp);
                                   $completereq = $this->addWhiteListedVarsBack($temp_completereq);
                                   $this->setRequestVariables($completereq,$type);
                               }
                           }

                       }
                   }
                   unset($this->completerequest);
                   unset($this->detected_whitelistedVars);
//                   return $result;
                   return false;
               }
               else
               {
                 //EMPTY  =>>> the request is empty
                 ////continue
                 //return true //safe to use
                   unset($this->detected_whitelistedVars);
                   return true;
               }
           }
           else{
               //white list string was detected
               unset($this->detected_whitelistedVars);
               return true;
           }
        }
        else
        {
            return true;
        }
    }


    //white list variables are removed from the scanning request
    //add them back to make sure the white listed vars are not ignored in the final requets
    public function addWhiteListedVarsBack($filtered_request)
    {
        if(!empty($this->detected_whitelistedVars))
        {
            foreach($this->detected_whitelistedVars as $whitelistedVarKey)
            {
                if(isset($this->orignal_request_backup[$whitelistedVarKey]))
                {
                    $filtered_request[$whitelistedVarKey] = $this->orignal_request_backup[$whitelistedVarKey];
                }
            }
            return $filtered_request;
        }else{
            return $filtered_request;
        }
    }

    //convert the flat array into the reqyest format thwat was recived
    public function getTheOriginalArrayStrucutre($filteredarray,$type = null)
    {
        $result = array();
        foreach($filteredarray as $key=>$value)
        {
            if(strpos($key,'#') !== false || strpos($key,'%23') !== false)
            {
                //has nested structure
                $converted_keys = $this->getConvertedKeys($key,$type);
                if(count($converted_keys) == 1)
                {
                    $result[$converted_keys[0]] = $value;
                }elseif(count($converted_keys) == 2) {
                    $result[$converted_keys[0]][$converted_keys[1]] = $value;
                }elseif(count($converted_keys) == 3) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]] = $value;
                }elseif(count($converted_keys) == 4) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]] = $value;
                }elseif(count($converted_keys) == 5) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]] = $value;
                }elseif(count($converted_keys) == 6) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]][$converted_keys[5]] = $value;
                }elseif(count($converted_keys) == 7) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]][$converted_keys[5]][$converted_keys[6]] = $value;
                }elseif(count($converted_keys) == 8) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]][$converted_keys[5]][$converted_keys[6]][$converted_keys[7]] = $value;
                }elseif(count($converted_keys) == 9) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]][$converted_keys[5]][$converted_keys[6]][$converted_keys[7]][$converted_keys[8]] = $value;
                }elseif(count($converted_keys) == 10) {
                    $result[$converted_keys[0]][$converted_keys[1]][$converted_keys[2]][$converted_keys[3]][$converted_keys[4]][$converted_keys[5]][$converted_keys[6]][$converted_keys[7]][$converted_keys[8]] [$converted_keys[9]]  = $value;
                }else {
                    return $this->prepareErrorMessage("the array has more than 10 layers");
                }
            }else{
                //has no nested structure
                $result[$key] = $value;
            }
        }
        return $result;
    }

    //scan the request against the rules
    public function scanRequests($request, $completedarray = null,$settings)
    {
        $key = key($request);
        $temp1 = array_values($request);
        $record = $temp1[0];
        $result = array();
        $rules = $this->getListofRules();
        if (!empty($rules))
        {
            foreach ($rules as $rule)
            {
                //add delimiters to the pattern for pre_match to work
                $pattern = $this->getFormattedPattern($rule['filter']);
                if (preg_match($pattern, $record, $matches))
                {
                    $this->detected_pentest = true;
                    //malicious pattern has been found in the request
                    $warning_text = $this->prepareWarningForPattern($matches[0], $record);
                    //clean the request
                    $cleanrequest = preg_replace($pattern,'',$record);
//                    echo "The cleaned request is ".$cleanrequest;
                    //calculate thge score based on the match
                    $score = $this->calcScore($this->ip,$rule['impact']);
                    //increas ethe attempt
                    $attempt = $this->calcAttempts($this->ip);
                    $result = $this->trackAttack($rule['attacktype'],$warning_text,$_FILES,$score,$attempt,$cleanrequest,$key,$settings);
                    if($result['status'] == 6)
                    {
                        //the ip has been banned
                        return $result;
                    } else if($result['status'] == 0 || $result['status'] == 2)
                    {
                        //error +continue
                        //return the continue status and the cleaned request
                        if($result['status'] == 0)
                        {
                            $this->errorLog('scan request',$result['info']);
                        }
                        $result1 =  $this->scanRequests($result['request'],null,$settings); //scan the clean request
                        return $result1;
                    }
                }
                else
                {
                    //no match == clean variables
                    //continue
                   $result = $this->preapreCustomMessage(5,"No malicious contents were detected in the request ");
                    $this->setCompleteRequest($key,$record);
                }
            }
            return $result;
        }
        else
        {
            $temp = $this->preapreCustomMessage(4,"The rules file is empty or does not exist, The request was not scanned  ");
            return $temp;
        }
    }

    //keeps information about the attacks perfromsed by the request
    //specifically used to keep track of attacks from the malicious contents in the request only
    // stores the score and attempt no and blocks them if the threshold is reached
    public function trackAttack($attacktype,$warningtext,$filearray,$score,$attempt,$cleanrequest,$key,$settings)
    {
        $subscription_status = oseFirewall::checkSubscriptionStatus(false);
        $temp = array();
        if(!empty($this->ip)) {
            $this->setVariables($attacktype,$warningtext,$key);
            $content = $this->attackFileContent($warningtext, $filearray, $score, $attempt);
            $result_file = $this->prepareTheAttackFile($content, $this->ip);
            if($subscription_status == true)
            {
                //premium users
                if($this->shouldblockIp($score,$attempt,$settings))
                {
                    //add an entry in the database
                    $result_db =  $this->ipmanagement->addBlockedIp($this->ip);
                    if($result_db && $result_file)
                    {
                        $result = $this->preapreCustomMessage(6,"The file and the database has been update and the Ip has been blocked "); //status == 1 for the ban page
                        //SEND EMAIL TO THE USER
                        $content_summary = $this->getCompleteAttackInformation($this->ip);
                        $this->sendEmailNotification('blocked',$content_summary,true);
                        return $result;
                    }else
                        if(!$result_db)
                        {
                            $result['status'] = 0;
                            $temp[$key] = $cleanrequest;
                            //return the cleaned request
                            $result['request'] = $temp;
                            $result['info'] = 'There was some problem in creating a database entry for the ip';
                            return $result;
                        }elseif(!$result_file)
                        {
                            $result['status'] = 0;
                            $temp[$key] = $cleanrequest;
                            //return the cleaned request
                            $result['request'] = $temp;
                            $result['info'] = 'There was some problem in creating a file entry for the ip';
                            return $result;
                        }
                }
                else
                {
                    //continue
                    $result = $this->prepareContinueMessage("The threshold has not been reached Continue..");
                    $temp[$key] = $cleanrequest;
                    //return the cleaned request
                    $result['request'] = $temp;
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,false);
                    return $result;
                }
            }else {
                //FOR FREE USERS
                if(!$result_file)
                {
                   //error in logging the attack for free users
                    $result['status'] = 0;
                    $temp[$key] = $cleanrequest;
                    //return the cleaned request
                    $result['request'] = $temp;
                    $result['info'] = 'FREE USER : There was some problem in creating a file entry for the ip';
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,false);
                    return $result;
                }else{
                    //free users
                    $result = $this->prepareContinueMessage("The attack has been logged");
                    $temp[$key] = $cleanrequest;
                    //return the cleaned request
                    $result['request'] = $temp;
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,false);
                    return $result;
                }
            }

        }else {
                //IP IS BLANK
                $result['status'] = 0;
                $temp[$key] = $cleanrequest;
                //return the cleaned request
                $result['request'] = $temp;
                $result['info'] = 'The Ip is blank';
                return $result;
            }

    }


    public function getCompleteAttackInformation($ip=false,$filename = false)
    {
        $result =array();
        if(!empty($filename))
        {
            $attackrecord = array();
            if(file_exists($filename))
            {
                require($filename);
            }
            $attackFileContents = $attackrecord;
        }else
        {
            $attackFileContents = $this->getAttackFilecontent($ip);
        }
        $result['ip'] = $attackFileContents[0]['ip'];
        $result['url'] = $this->getSummaryArray($attackFileContents,'url');
        $result['referer'] = $this->getSummaryArray($attackFileContents,'referer');
        $result['useragent'] = $this->getSummaryArray($attackFileContents,'useragent');
        $result['browser'] = $this->getSummaryArray($attackFileContents,'browser');
        $result['attackdatetime'] = $this->getSummaryArray($attackFileContents,'attackdatetime');
        $result['attacktype'] = $this->getSummaryArray($attackFileContents,'attacktype');
        $result['attack'] = $this->getSummaryArray($attackFileContents,'attack');
        $result['variables'] = $this->getSummaryArray($attackFileContents,'variables');
        $result['files'] = $this->getSummaryArray($attackFileContents,'files');
        $temp_lastrecord =end($attackFileContents);
        $result['score'] =$temp_lastrecord['score'];
        $result['attempt'] = $temp_lastrecord['attempt'];
        return $result;
    }

    public function getSummaryArray($attackFileContents,$par)
    {
        $return = array();
        if(!empty($attackFileContents))
        {
            foreach ($attackFileContents as $record) {
                if(isset($record[$par]))
                {
                    if(is_array($record[$par]))
                    {
                        foreach($record[$par] as $val)
                        {
                            $return[$par][]  = $val;
                        }
                    }else{
                        $return[$par][] = $record[$par];
                    }
                }
         }
        }
        return $return[$par];
    }

    public function sendEmailNotification($type,$content,$mode = false)
    {
        oseFirewallBase::callLibClass('fwscannerv7','emailNotificationMgmt');
        $fs= new emailNotificationMgmt();
        $result_email = $fs->sendEmail($type,$content,$mode);
        return $result_email;
    }

    public function setCompleteRequest($key,$value)
    {
        $this->completerequest[$key] = $value;
    }

    public function getCompleteRequest()
    {
        return $this->completerequest;
    }

    //determine whether the ip shoudl be blocked based on the score and the attempts
    public function shouldblockIp($score, $attempt,$settings)
    {
        if(isset($settings[33]))
        {
            $max_attempts = $settings[33];
        }else {
            $max_attempts = DEFAULT_ATTEMPT_THRESHOLD;
        }
        $fwsensitivity = (int)$settings[9];
        $mode = (int)$settings[17];
        if($mode == 1)
        {
            //block mode is on
            if(($fwsensitivity <= $score) && ($attempt>= $max_attempts))
            {
                return true;
            }
            else
            {
                return false;
            }
        }else {
            //filter mode
            return false;
        }
    }

    //check if the request has whiteliststring if yes do not scan the request
    public function hasWhiteListString() //complete array of request
    {
        $stringlist = null;
        $stringlist =  $this->whitelistmgmt->getContentOfFiles('STRING');
        if(!empty($stringlist))
        {
            foreach($stringlist as $value)
            {
                $formatedpattern = $this->getFormattedPattern($value['string']);
                if(isset($_SERVER['QUERY_STRING']))
                {
                    $decodedRequest = urldecode($_SERVER['QUERY_STRING']);
                    if(preg_match($formatedpattern,$decodedRequest))
                    {
                        return true;
                    }
                }
            }
            return false; // no whitelist string was found
        }else {
            return false;
        }
    }

    //check if the the white listed variables from the user exists in the request
    public function removeWhiteListVariable($temp,$type)
    {
        $variablelist = null;
        $variablelist = $this->whitelistmgmt->getContentOfFiles('VARIABLE');
        if(empty($variablelist))
        {
            return $temp;
        }else
        {
            $whiteListVariables = $this->getWhiteListedVariables($variablelist,$type);
            foreach($temp as $reqkey => $reqvalue)
            {
                if(in_array(urldecode($reqkey),$whiteListVariables))
                {
                    array_push($this->detected_whitelistedVars,$reqkey);
                    unset($temp[$reqkey]);
                }
            }
            return $temp;
        }
    }

    public function getWhiteListedVariables($variablelist,$type)
    {
        $whiteListVariables = array();
        foreach($variablelist as $record)
        {
            $temp = explode('.',$record['variable']);
            if($temp[0] == $type || $temp[0] == strtolower($type))
            {
                array_push($whiteListVariables,$temp[1]);
            }
        }
        return $whiteListVariables;
    }

    //the keys are in format : key1#key2#key3
    //returns the keys in the form of an array
    public function getConvertedKeys($key,$type = null)
    {
        if(!empty($key))
        {
            if($type !==null)
            {
                $result = explode('%23',$key);

            }else
            {
                $result = explode('#',$key);
            }
            return $result;

        }
    }

    //converts a nested array into one dimensional array
    public function array_flatten($array, $key_temp = null) {
        if (!is_array($array)) {
            return FALSE;
        }
        $result = array();
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                if(!is_null($key_temp))
                {
                    $newkey = $key_temp."#".$key;
                }else {
                    $newkey = $key;
                }
                $result = array_merge($result, $this->array_flatten($value,$newkey));
            }
            else {
                if(!is_null($key_temp))
                {
                    $newkey = $key_temp."#".$key;
                }else {
                    $newkey = $key;
                }
                $result[$newkey] = $value;
            }
        }
        return $result;
    }

    //convert the pattern so that it can be used with preg_match
    public function getFormattedPattern($pattern)
    {
        $result = "/" . $pattern . "/im";
        return $result;
    }

    //decode an array
    public function codeArray($array,$type)
    {
        if($type =='encode')
        {
            $result = array();
            foreach($array as $key =>$value)
            {
                $result[urlencode($key)] = urlencode($value);
            }
            return $result;
        }else {
            $result = array();
            foreach($array as $key =>$value)
            {
                $result[urldecode($key)] = urldecode($value);
            }
            return $result;
        }

    }

    public function codeArrayWithStructure($array,$type)
    {
        $flatarray= $this->array_flatten($array);
        if($type == 'decode')
        {
            $result = array();
            foreach($flatarray as $key =>$value)
            {
                $result[urldecode($key)] = urldecode($value);
            }
            $original_struct = $this->getTheOriginalArrayStrucutre($result);
            return $original_struct;
        }else {
            $result = array();
            foreach($flatarray as $key =>$value)
            {
                $result[urlencode($key)] = urlencode($value);
            }
            $original_struct = $this->getTheOriginalArrayStrucutre($result,'encode');
            return $original_struct;
        }
    }

    //returns the value of firewall sensitivity from the database
    public function getFirewallSensitivity()
    {
        $query = "SELECT `value` FROM `#__osefirewall_fwscannerv7Config` WHERE `type`= 'sensitivity' ";
        $this->db->setQuery($query);
        $result = $this->db->loadObject();
        if(!empty($result->value) && ($result->value!== 0))
        {
            return $result->value;
        } else {
            return DEFUALT_FIREWALL_SENSITIVITY;
        }
    }

    //get the no of attempts for a specific ip and user
    public function getAttemptFromLocalFiles($ip)
    {
        $filepath = OSE_WEBLOGFOLDER.ODS.$ip.ODS.'blocked.php';
        if(file_exists($filepath))
         {
            $content = $this->getAttackFilecontent($ip);
             $temp_attempst_latestrecord =end($content);
            return $temp_attempst_latestrecord['attempt'];
         }else {
            return 0;
        }
    }

    //get the score from the local file
    public function getScoreFromLocalFiles($ip)
    {
        $filepath = OSE_WEBLOGFOLDER.ODS.$ip.ODS.'blocked.php';
        if(file_exists($filepath))
        {
            $content = $this->getAttackFilecontent($ip);
            $totalCount = end($content);
            return $totalCount['score'];
        }else {
            return 0;
        }
    }

    //get the warning text array from the local file
    public function getWarningTextFromFile($ip)
    {
        $filepath = OSE_WEBLOGFOLDER.ODS.$ip.ODS.'blocked.php';
        if(file_exists($filepath))
        {
            $content = $this->getAttackFilecontent($ip);
            $temp_warning_text =end($content);  //TODO CHNAGE THE WARNING TEXT FOR ALL THE ARRAYS
            return $temp_warning_text['attack'];
        }else {
            return array();
        }
    }

    //calculathe score of the attack
    //add the previous score and the new score
    public function calcScore($ip,$newscore)
    {
        $oldscore = $this->getScoreFromLocalFiles($ip);
        $total = $oldscore +$newscore;
//        echo "total score is ".$total;
        return $total;
    }

    //calculate the attempts
    //new attempt count is previous attempt count + 1
    public function calcAttempts($ip)
    {
        $oldattemptcount = $this->getAttemptFromLocalFiles($ip);
        $total = $oldattemptcount +1;
//        echo "total attempt is ".$total;
        return $total;
    }

    //prepare warning text for the attack file
    public function prepareWarningForPattern($matchedpattern, $request)
    {
        unset($temp1);
        unset($temp2);
        $temp1 = str_replace("<", "&lt;", $request);
        $temp2 = str_replace(">", "&gt;", $temp1);
        $temp3 = str_replace("'", "&#039", $temp2);
        $temp4 = str_replace('"', "&quot", $temp3);
        $temp5 = str_replace('&', "&amp", $temp4);
        $replacementmsg = '<span class="text-danger">' . $matchedpattern . '</span>';
        $result = str_replace($matchedpattern, $replacementmsg, $temp5);
        //check the file for previous attempts and append the new attacks
        $warning_text = array();
        array_push($warning_text,$result);
        return $warning_text;
    }

    //set the local variables to store the infomation about the request
    public function setVariables($attacktype,$warningtext = null,$key = false)
    {
        $this->setTargetURL();
        $this->setReferer();
        $this->setUserAgent();
        $this->setAttackType($attacktype);
        $this->setBrowser();
        $this->setDateandTime();
        $this->setWarningTexts($warningtext);
        $this->setOriginalRequestVariablesLog($key);

    }
    public function setBrowser()
    {
        $current_request_browser = $this->getCurrentBrowser();
        $current_browserArray= array($current_request_browser);
        $this->broswer = $current_browserArray;

    }

    //RECORD ALL THE DETAILS ABOUT THE ATTACK
    public function logAttacks($attacktype,$warningtext,$filearray,$attempt,$score =100)
    {
        $subscription_status = oseFirewall::checkSubscriptionStatus(false);
        if(!empty($this->ip))
        {
            $this->setVariables($attacktype,$warningtext);
            $content = $this->attackFileContent($warningtext,$filearray,$score,$attempt);
            $result_file = $this->prepareTheAttackFile($content,$this->ip);
            if(OSE_CMS == 'joomla')
            {
                oseFirewall::callLibClass('fwscannerv7','ipManagement');
                $ipmanagement = new ipManagement();
                if($subscription_status == true)
                {
                    $result_db = $ipmanagement->addBlockedIp($this->ip);
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,true);
                }else {
                    $result_db = true;
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,false);
                }
            }else {
                if($subscription_status == true)
                {
                    //TODO FIX THE USE OF VARIABLE IPMANAGEMENT
                    $result_db = $this->ipmanagement->addBlockedIp($this->ip);
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,true);

                }else {
                    $result_db = true;
                    $content_summary = $this->getCompleteAttackInformation($this->ip);
                    $this->sendEmailNotification('blocked',$content_summary,false);
                }
            }
            $result = $result_db && $result_file;
            if($result)
            {
                $message = "Attack has been logged in file and database";
                $temp = $this->prepareSuccessMessage($message);
            }
            else
            {
                if($result_file)
                {
                    $message = "Problem in recording the attack in the database";
                    $temp = $this->prepareErrorMessage($message);
                }else
                {
                    $message = "Problem in recording the attack in the file";
                    $temp = $this->prepareErrorMessage($message);
                }
            }
        }else {

            $message = "The ip is null";
            $temp = $this->prepareErrorMessage($message);
        }

        return $temp;
    }
    public function setWarningTexts($warning_text)
    {
        if(!is_array($warning_text)) {
            $this->warningtext= array($warning_text);
        }else {
            $this->warningtext = $warning_text;
        }
    }
    public function getWarningText()
    {
        return $this->warningtext;
    }

    public function setOriginalRequestVariablesLog($request)
    {
        if(empty($request))
        {
            $this->originalrequest_log = "N/A";
            return ;
        }
        $type_temp = false;
        if(!empty($this->type))
        {
            $type_temp = $this->type;
        }
        $current_request_log = array();
        if(!is_array($request)) {
            $current_request_log = array($type_temp.".".$request);
        }else {
            foreach($request as $key=>$value)
            {
                $current_request_log[] = $type_temp.".".$key;
            }
        }
        $this->originalrequest_log = $current_request_log;
    }


    public function getOriginalRequestVariablesLog()
    {
        return $this->originalrequest_log;
    }

    //problem with formatting may be
    public function attackFileContent($warning_text, $file_info = array(),$score = 100,$attempt=1)  //TODO FIX THE ATTEMT COUNT
    {
        $temp_old_content = $this->getAttackFilecontent($this->ip);
        $new_content = array();
        if(empty($file_info))
        {
            $file_info = 'N/A';
        }
        $current_content = array(
            'ip' => $this->ip,
            'url' => $this->getUrl(),
            'referer' => $this->getReferer(),
            'useragent' => $this->getUserAgent(),
            'browser' => $this->getBrowser(),
            'attackdatetime' => $this->getDateAndTime(),
            'attacktype' => $this->getAttackType(),
            'attack' => $this->getWarningText(),
            'variables' => $this->getOriginalRequestVariablesLog(),
            'files' => $file_info,
            'score' =>$score,
            'attempt'=>$attempt,
        );
        if(empty($temp_old_content) || $temp_old_content==false)
        {
            $new_content = array($current_content);
        }else{
            $temp_old_content[] = $current_content;
            $new_content = $temp_old_content;
        }
        unset($temp_old_content);
        unset($current_content);
        return $new_content;
    }


    public function clearOldAttackInfo($contents)
    {
        return array_splice($contents,-40);
    }

    //write the content to the file
    public function prepareTheAttackFile($content, $ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP) === false) {
            //create the web log folder
            if (!file_exists(OSE_WEBLOGFOLDER)) {
                $this->makeDirs(OSE_WEBLOGFOLDER,0777,true);

            }
            //create folder for the ip address
            $ipfolder = OSE_WEBLOGFOLDER . ODS . $ip;
            if (!file_exists($ipfolder)) {
                $this->makeDirs($ipfolder,0777,true);
            }

            $filepath = OSE_WEBLOGFOLDER . ODS . $ip . ODS . "blocked.php";
            if(file_exists($filepath))
            {
                $fileExists = true;
            }else{
                $fileExists = false;
            }
            if(!empty($content) && count($content)>40)
            {
                $temp_content = $this->clearOldAttackInfo($content);
                unset($content);
                $content = $temp_content;
            }
            $contenttoput = "<?php\n" . '$attackrecord = ' . var_export($content, true) . ";";
            $result = file_put_contents($filepath, $contenttoput);
            if(!$fileExists)
            {
                chmod($filepath,0777);
            }
            return ($result == false) ? false : true;
        } else
            return false;
    }


    public function getCurrentDateTime()
    {
        $result = array();
        $result['datetime'] = date('dmyHis');
        $result['date'] = substr($result['datetime'], 0, 2);
        $result['month'] = substr($result['datetime'], 2, 2);
        $result['year'] = substr($result['datetime'], 4, 2);
        $result['hour']  = substr($result['datetime'], 6, 2);
        return $result;
    }

    public function setDateandTime()
    {
        $result = $this->getCurrentDateTime();
        $current_DateTimeArray= array($result['datetime']);
        $this->datetime = $current_DateTimeArray;
    }

    public function getDateAndTime()
    {
        return $this->datetime;
    }

    //returns the information related to attack
    public function getAttackFilecontent($ip)
    {
        $attackrecord = array();
        $filepath = OSE_WEBLOGFOLDER . ODS . $ip.ODS.'blocked.php';
        if(file_exists($filepath))
        {
            require($filepath);
            if(!empty($attackrecord) && count($attackrecord)>40)
            {
                $attackrecord = $this->clearOldAttackInfo($attackrecord);
                return $attackrecord;
            }else{
                return $attackrecord;
            }
        }else {
            return false;
        }
    }

    public function createConfigTable()
    {
        $query = "CREATE TABLE IF NOT EXISTS `#__osefirewall_fwscannerv7Config` (
                          `id`      INT(11)      NOT NULL AUTO_INCREMENT,
                          `key` VARCHAR(200) NOT NULL UNIQUE,
                          `value` TEXT NOT NULL,
                          `type` VARCHAR(200) NOT NULL,
                          PRIMARY KEY (`id`)
                        )
                          ENGINE = InnoDB  DEFAULT CHARSET = utf8  AUTO_INCREMENT = 1; ";
        $this->db->setQuery($query);
        $results = $this->db->loadObject();
        return $results;
    }

    public function getAdmineEmail()
    {
        $admin_email = get_option( 'admin_email' );
        if(!empty($admin_email))
        {
            return $admin_email;
        }
        else {
            return 0;
        }
    }

    protected function getCurrentReferer()
    {
        if (isset ($_SERVER['HTTP_REFERER'])) {
            $temp_referer = $_SERVER['HTTP_REFERER'];
        } else {
            $temp_referer = 'N/A';
        }
        return $temp_referer;
    }

    public function setReferer()
    {
        $current_referr = $this->getCurrentReferer();
        $current_refererArray= array($current_referr);
        $this->referer = $current_refererArray;
    }

    public function getReferer()
    {
        return $this->referer;
    }

    protected function setTargetURL()
    {
        $current_url = $this->getCurrentTargetUrl();
        $current_urlArray= array($current_url);
        $this->url = $current_urlArray;
    }

    public function getCurrentTargetUrl()
    {
        $query = (!empty($_SERVER['QUERY_STRING'])) ? str_replace('?' . $_SERVER['QUERY_STRING'], '', $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']) : '';
        $temp = ((!empty($_SERVER['HTTPS'])) ? "https://" : "http://") . $query;
        return $temp;
    }

    public function getUrl()
    {
        return $this->url;
    }


    public function getCurrentUserAgent()
    {
        if (isset ($_SERVER['HTTP_USER_AGENT'])) {
            $temp = $_SERVER['HTTP_USER_AGENT'];
        } else {
            $temp = 'N/A';
        }
        return $temp;
    }
    protected function setUserAgent()
    {
        $current_useragent = $this->getCurrentUserAgent();
        $current_useragentArray= array($current_useragent);
        $this->useragent = $current_useragentArray;

    }

    public function getUserAgent()
    {
        return $this->useragent;
    }


    //gets the browser name from the server variable
    public function getCurrentBrowser()
    {
        $user_agent = ($_SERVER['HTTP_USER_AGENT']);
        if (strpos($user_agent, 'Opera') || strpos($user_agent, 'OPR/')) {
            $this->browser = 'Opera';
            return $this->browser;
        } elseif (strpos($user_agent, 'Edge')) {
            $this->browser = 'Edge';
            return $this->browser;
        } elseif (strpos($user_agent, 'Chrome')) {
            $this->browser = 'Chrome';
            return $this->browser;
        } elseif (strpos($user_agent, 'Safari')) {
            $this->browser = 'Safari';
            return $this->browser;
        } elseif (strpos($user_agent, 'Firefox')) {
            $this->browser = 'Firefox';
            return $this->browser;
        } elseif (strpos($user_agent, 'MSIE') || strpos($user_agent, 'Trident/7')) {
            $this->browser = 'Internet Explorer';
            return $this->browser;
        }
        return 'Other';
    }
    public function getBrowser()
    {
        return $this->browser;
    }

    public function setAttackType($attackarray)
    {
        if(!is_array($attackarray))
        {
            $attackarray = array($attackarray);
        }
        $this->attacktype = $attackarray;
    }

    public function getAttackType()
    {
        return $this->attacktype;
    }

    public function setRequestVariables($request,$type)
    {
        $this->type = $type;
        if($type == 'POST')
        {
            $_POST = $request;
        }else {
            $_GET = $request;
        }
    }

    public function getRequestVariables($type)
    {
        if ($type == 'POST') {
            return $_POST;
        }else {
            return $_GET;
        }
    }

    //generate the zip of the weblof in the foler weblogbackup
    public function generateZipofWeblog()
    {
        oseFirewallBase::callLibClass('gitBackup', 'Process');
        $path = $this->getWebLogBackupZipName();
        $cmd = "cd " . CENTRORABACKUP_FOLDER . ";tar -zcf " . $path . " Weblog/logBackup/";
        $output = $this->runShellCommand($cmd);
        if (empty($output['stderr']) && file_exists($path)) {
            $cmd = "cd " . OSE_ABSPATH . ";";
            $this->runShellCommand($cmd);
            $result['status'] = 1;
            $result['message'] = "The zip file of the website has been generated";
            return $result;
        } else {
            $result['status'] = 0;
            $result['message'] = "There was some problem in generating the zip file: " . $output['stderr'];
            return $result;
        }
    }
    public function getWebLogBackupZipName()
    {
        $date = new DateTime();
        $start = $date->getTimestamp();
        $path = OSE_WEBLOG_BACKUPFOLDER.ODS.'weblog-'.$start.'-.tar.gz';
        return $path;
    }

    public function manageWebLog()
    {
        $temp = $this->generateZipofWeblog();
        if ($temp['status'] == 1) {
            $this->deletefiledinWebLogFolder();
        }
    }

    public function deletefiledinWebLogFolder()
    {
        rmdir(OSE_WEBLOGFOLDER); //not enough permissions
    }

    //setup to run command line
    protected function runShellCommand($command, $args = '')
    {
        $functionArgs = func_get_args();
        array_shift($functionArgs);
        $result = $this->runProcess($command);
        return $result;
    }

    //setup for command line
    private function runProcess($cmd)
    {
        $dyldLibraryPath = getenv("DYLD_LIBRARY_PATH");
        if ($dyldLibraryPath != "") {
            putenv("DYLD_LIBRARY_PATH=");
        }
        $process = new Process($cmd, $this->workingDirectoryRoot);
        if ($this->gitProcessTimeout !== null) {
            $process->setTimeout($this->gitProcessTimeout);
        }
        $process->run();
        $result = array(
            'stdout' => $process->getOutput(),
            'stderr' => $process->getErrorOutput()
        );
        putenv("DYLD_LIBRARY_PATH=$dyldLibraryPath");
        if ($result['stdout'] !== null) $result['stdout'] = trim($result['stdout']);
        if ($result['stderr'] !== null) $result['stderr'] = trim($result['stderr']);

        return $result;
    }


    public function getSystemStat()
    {
        echo "the load on the server is";
        echo "<br/>";
        echo "<pre>";
        print_r(sys_getloadavg());
        echo "</pre>";
        echo "<br/>";
        echo "the memory usage is : " . memory_get_usage();
        echo "<br/>";
    }

    public function getCountofRules()
    {
        $query = "SELECT COUNT(*) as `count` FROM `#__osefirewall_advancerules` ";
        $this->db->setQuery($query);
        $result = $this->db->loadResult();
        return ($result['count'] > 0) ? $result['count'] : false;
    }

    public function getListOfFolders()
    {
        $directories = glob(OSE_WEBLOGFOLDER . '/*' , GLOB_ONLYDIR);
        return $directories;
    }

    public function getListofFiles($folder)
    {
        $files = array_diff(scandir($folder), array('.', '..','.DS_Store'));  // need to neglect the temporary files
        return $files;
    }


    public function prepareListOfattackFiles()
    {
        $this->finallist = array();
        $path = OSE_WEBLOGFOLDER;
        if(!file_exists($path))
        {
            return false;
        }
        $objects = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path), RecursiveIteratorIterator::SELF_FIRST);
        $reg = new RegexIterator($objects, '/^.+\.php$/i', RecursiveRegexIterator::GET_MATCH);
        foreach ($reg as $name => $object) {
            array_push($this->statsfileslist, $object[0]);
        }
        return $this->statsfileslist;
    }

    //debugging
    public function test()
    {
        print_r($this->ipstats);
        echo "<br/>";
        print_r($this->browserstats);
        echo "<br/>";
        print_r($this->uastats);
        echo "<br/>";
        print_r($this->attacktypestats);
        echo "<br/>";
        print_r($this->attackstats);
        echo "<br/>";
        print_r($this->datesstats);
        echo "<br/>";
        print_r($this->monthsstats);
        echo "<br/>";
        print_r($this->yearstats);
        echo "<br/>";
        print_r($this->hoursstats);
        echo "<br/>";
    }

    //requires the files and returns the content
    public function getRequireAttackfile($filename)
    {
        $attackrecord = array();
        if (file_exists($filename)) {
            require($filename);
        }
        return $attackrecord;
    }

    //return the no of attacks that have occured
    public function getNoOfAttacks()
    {
        return $this->attackstats;
    }

    public function timeAnalysisofAttacks($attackfilesummary)
    {
        $montharray = array();
        $datearray = array();
        $yeararray = array();
        $timearray = array();
        $montharray = array_count_values($montharray);
        arsort($montharray);

        $datearray = array_count_values($datearray);
        arsort($datearray);

        $yeararray = array_count_values($yeararray);
        arsort($yeararray);

        $timearray = array_count_values($timearray);
        arsort($timearray);

        $timeanalysis = array(
            'month' => $montharray,
            'year'=> $yeararray,
            'date'=>$datearray,
            'time'=>$timearray,
        );
        return $timeanalysis;
    }

    public function dateAnalysis()
    {
        $result = array_count_values($this->datesstats);
        arsort($result);
        return $result;
    }

    public function monthAnalysis()
    {
        $result = array_count_values($this->monthsstats);
        arsort($result);
        return $result;
    }

    public function yearAnalysis()
    {
        $result = array_count_values($this->yearstats);
        arsort($result);
        return $result;
    }

    public function hourAnalysis()
    {
        $result = array_count_values($this->hoursstats);
        arsort($result);
        return $result;
    }

    public function useragentAnalysis()
    {
        $result = array_count_values($this->uastats);
        arsort($result);
        return $result;
    }

    public function browserAnalysis()
    {
        $result = array_count_values($this->browserstats);
        arsort($result);
        return $result;
    }


    //code for debugging
    public function completeAnalysis()
    {
        echo "USER AGENTS  : ";
        $temp = $this->useragentAnalysis();
        print_r($temp);
        echo "<br/>";

        echo "browsers : ";
        $temp = $this->browserAnalysis();
        print_r($temp);
        echo "<br/>";

        echo "date : ";
        $temp = $this->dateAnalysis();
        print_r($temp);
        echo "<br/>";

        echo "month : ";
        $temp = $this->monthAnalysis();
        print_r($temp);
        echo "<br/>";

        echo "year : ";
        $temp = $this->yearAnalysis();
        print_r($temp);
        echo "<br/>";

        echo "hour : ";
        $temp = $this->hourAnalysis();
        print_r($temp);
        echo "<br/>";

    }

    //CODE TO PROVIDE ANTI SPAMMING SERVICES
    public function antispamProtection()
    {
        $this->loadLibrary();

        //check if the ip has been already spam checked
        $isspamcheck = $this->ipmanagement->isspamcheck($this->ip);
        if($isspamcheck['isspam'] == 0)
        {
            //if the record is not present or the ip is checked and is not a spam
            $date = new DateTime();
            $current_timestamp = $date->getTimestamp();
            //calculate the check for time if the ip is already checked
            $timestamp_diff = $current_timestamp - $isspamcheck['timestamp'];
            if($isspamcheck['ischecked'] == 0 || ($isspamcheck['ischecked'] == 1 && ($timestamp_diff > 86400))) //24 hours time diffrence
            {
                //perfrom check if the ip is not checked or if the timstamp is greater than 24 hours from the current time stamp
                $data = array();
                $data["ip"] = $this->ip;  //this->ip
                $data["f"] = 'json';
                $json_return = $this->posttoSFS($data);
                $result = oseJSON:: decode($json_return);
                if (!isset($result->ip->confidence))
                {
                    if($isspamcheck['ischecked'] == 1)
                    {
                        $this->ipmanagement->updateSpamCheck($this->ip,1,0,$current_timestamp);
                    }else {
                        $this->ipmanagement->insertSpamCheck($this->ip,0,1,0,$current_timestamp);
                    }
                    $this->unsetVariables();
                }
                elseif ($result->ip->appears == 1 && $result->ip->confidence >= (int)$this->sfs_confidence) // Was the result was registered
                {
                    //if confidence is set then block the ip
                    if($isspamcheck['ischecked'] == 1)
                    {
                        $this->ipmanagement->updateSpamCheck($this->ip,1,1,$current_timestamp);
                    }else {
                        if(oseFirewallBase::checkSubscriptionStatus(false))
                        {
                            $this->ipmanagement->insertSpamCheck($this->ip,2,1,1,$current_timestamp);
                        }else{
                            $this->ipmanagement->insertSpamCheck($this->ip,0,1,1,$current_timestamp);
                        }
                    }
                        //update the blocked record in ip management table as well
                    $subscription_status = oseFirewall::checkSubscriptionStatus(false);
                    if($subscription_status)
                    {
                        $score = $this->calcScore($this->ip,100);
                        $attempts = $this->calcAttempts($this->ip);
                        if($attempts<MAX_ATTEMP)
                        {
                            $attempts = MAX_ATTEMP;
                        }
                        $this->logAttacks(array("11"), array('IP Spamming'), array(), $attempts, $score); //set the attempt count to 10 straigth away
                    }else{
                        $score = $this->calcScore($this->ip,10);
                        $attempts = $this->calcAttempts($this->ip);
                        $this->logAttacks(array("11"), array('IP Spamming'), array(), $attempts, $score); //set the attempt count to 10 straigth away
                    }
                    $this->unsetVariables();
                    if($subscription_status == true)
                    {
                        $this->showBanPage();
                    }
                }
                else
                {
                    //TODO UOPDATE THE SPAM CHECK
//                    $message = "The IP is safe";
                    return true;
                }
            }
            else
            {
//                $message = "The IP is already checked";
                $this->unsetVariables();
                return true;
            }
        }
        else
        {
            //spammer is trying to access the website
            $subscription_status = oseFirewall::checkSubscriptionStatus(false);
            if($subscription_status)
            {
                $score = $this->calcScore($this->ip,100);
                $attempts = $this->calcAttempts($this->ip);
                if($attempts<MAX_ATTEMP)
                {
                    $attempts = MAX_ATTEMP;
                }
                $this->logAttacks(array("11"), array('IP Spamming'), array(), $attempts, $score); //set the attempt count to 10 straigth away
            }else{
                $score = $this->calcScore($this->ip,10);
                $attempts = $this->calcAttempts($this->ip);
                $this->logAttacks(array("11"), array('IP Spamming'), array(), $attempts, $score); //set the attempt count to 10 straigth away
            }
            if($subscription_status == true)
            {
                $this->showBanPage();
            }
        }
    }

    public function unsetVariables()
    {
        unset ($data);
        unset ($json_return);
        unset ($result);
    }

    public function prepareSuccessMessage($message)
    {
        $result['status'] = 1;
        $result['info'] = $message;
        return $result;
    }

    public function prepareErrorMessage($message)
    {
        $result['status'] = 0;
        $result['info'] = $message;
        return $result;
    }
    public function prepareContinueMessage($message)
    {
        $result['status'] = 2;
        $result['info'] = $message;
        return $result;
    }

    public function preapreCustomMessage($status,$info)
    {
        $result['status'] = $status;
        $result['info'] = $info;
        return $result;
    }

    protected function posttoSFS($data)
    {
        $Url = "http://www.stopforumspam.com/api?" . http_build_query($data);
        $Curl = curl_init();
        curl_setopt($Curl, CURLOPT_URL, $Url);
        curl_setopt($Curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($Curl, CURLOPT_TIMEOUT, 4);
        curl_setopt($Curl, CURLOPT_FAILONERROR, 1);
        $ResultString = curl_exec($Curl);
        curl_close($Curl);
        unset ($Url);
        unset ($Curl);
        return $ResultString;
    }

    protected function composeResult($impact, $content, $rule_id, $attackTypeID, $keyname, $type = 'bs')
    {
        $return = array();
        $return ['impact'] = $impact;
        $return ['attackTypeID'] = $attackTypeID;
        $return ['detcontent_content'] = $content;
        $return ['keyname'] = $keyname;
        $return ['rule_id'] = $rule_id;
        $return ['type'] = $type;
        return $return;
    }

    public function bruteForceProtectionCheck()
    {
        add_action('wp_login_failed', array($this, 'bruteForceProtection'));
        $this->loadLibrary();
    }

    //Protect against the brute force attack
    //keep the count of failed login for a specific ip
    public function bruteForceProtection($authUser)
    {
            //get brute force configurations
            $settings = $this->getCompleteFirewallSettingsFromDb();
            $maxfail = $settings['info'][25];
            $timeFrame = $settings['info'][26];
            $userip = $this->ip;
            //check for the user
            $timestamp = $this->getCurrentTimeStamp();
            $this->recordLoginAttempts($userip,$authUser,$timestamp,$maxfail,$timeFrame);
    }

    public function prepareContentArray($ip, $username, $attempt)
    {
        $content = array(
            'ip' => $ip,
            'username' => $username,
            'attempt' => $attempt,
        );
        return $content;
    }

    public function insertIntoDbTest($content)
    {
        $result = $this->db->addData('insert', '#__osefirewall_bftest', '', '', $content);
        return $result;
    }

    public function getMaxAttempts($ip, $username)
    {
        $query = "SELECT MAX(`attempt`) AS attempt FROM `#__osefirewall_bftest` WHERE `ip`=" . $this->db->quoteValue($ip) . " AND `username`=" . $this->db->quoteValue($username);
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }

    public function fileTest($contents)
    {
        $date = new DateTime();
    	 $current_timestamp = $date->getTimestamp();
        foreach($contents as $content)
        {
            $result =   $this->recordLoginAttempts($content['ip'],$content['username'],$current_timestamp,9,1);
        }

        $result1 = $this->getAttemptsCountforUsername("100.100.100.109", "admin1");
        return $result1;

    }

    public function getCurrentTimeStamp()
    {
        $date = new DateTime();
        $current_timestamp = $date->getTimestamp();
        return $current_timestamp;
    }

    //FILE APPROACH : keeps tracks of failed login attempts for each ip and username
    public function recordLoginAttempts($ip, $username, $timestamp,$maxattempt,$timeframe)  ///TODO : EROOR HANDLING
    {
        //insert each failed login attempt in the file
        $result = $this->insertIntoFiles($ip, $username, $timestamp,$maxattempt,$timeframe);
        return $result;
    }

    //writes the count of attempts in the file for each ip and username
    public function insertIntoFiles($ip, $username, $timestamp,$maxattempt,$timeframe)
    {
        $result = null;
        $ipfolder = OSE_WEBLOGFOLDER . ODS . $ip;
        //check if the folder for the ip exists
        if (!file_exists($ipfolder)) {
            $this->makeDirs($ipfolder,0777,true);
        }
        $filepath = OSE_WEBLOGFOLDER . ODS . $ip . ODS . "bruteforceattempts.php";
        //check if the record file exists for the attacker
        if (!file_exists($filepath)) {
            //THE FILE DOES NOT EXIST
            //FIRST ATTACK FROM AN IP
            //prepare the content
            $attempt = 1; //attemp = 0 since the file does not exists
            $content = $this->formatContent($username, $timestamp, $attempt);
            //write the file
            $result = $this->writeAttemptsInFile($ip, $content);
        } else {
            //if the file already exists
            //check if the array for a specific user exists
            $data = $this->getAttemptsCount($ip);
            if (empty($data[$username])) {
//                echo "THE RECORD FOR THE USERNAME DOES NOT EXIST";
                //THE RECORD FOR THE USERNAME DOES NOT EXISTS
                //prepare the content
                $attempt = 1; //since the username does not have an entry it should be set to  1
                //get the content of the file
                $oldcontent = $this->getAttemptsCount($ip);
                //adds the new element to the old one
                $temp = $this->preapreUpdatedContent($username,$timestamp,$attempt,$oldcontent);
                //write the updated array into the file
                $result = $this->writeAttemptsInFile($ip, $temp);
            } else {
                //the record for the username does exists
                //prepare the content by increasing the count of attempt
                $date = new DateTime();
                $current_timestamp = $date->getTimestamp();
                //check if the time of the attacks
                if($this->timeKeeper($data[$username]['timestamp'],$current_timestamp,$timeframe))
                {
//                    echo "INSIDE THE TIME HAS NOT EXPIRED";
                    //increase the attack count
                    $new_count = $data[$username]['attempt'] + 1;
                    //check if the count is greater than the limit set by the user
                    if ($new_count >= $maxattempt)
                    {
                        //block the ip
                        $old_content = $this->getAttemptsCount($ip);
                        $old_content[$username]['attempt'] = $maxattempt;
                        $result = $this->writeAttemptsInFile($ip, $old_content);
                        $subscription_status = oseFirewallBase::checkSubscriptionStatus(false);
                        if($subscription_status)
                        {
                            $score = $this->calcScore($this->ip,100);
                            $attempts = $this->calcAttempts($this->ip);
                            if($attempts<MAX_ATTEMP)
                            {
                                $attempts = MAX_ATTEMP;
                            }
                            $result_log = $this->logAttacks(array('15'),array('BruteForce Attack'),null,$attempts,$score);

                        }else{
                            $score = $this->calcScore($this->ip,10);
                            $attempts = $this->calcAttempts($this->ip);
                            $result_log= $this->logAttacks(array('15'),array('BruteForce Attack'),null,$attempts,$score);
                        }
                        if($result_log['status'] == 1)
                        {
                            $subscription_status = oseFirewall::checkSubscriptionStatus(false);
                            if($subscription_status == true)
                            {
                                $this->showBanPage();
                            }
                        }else {
                            return $result_log;
                        }
                        //BLOCK THE USER
                    } else {
//                        echo "THE ATTACK COUNT IS LESS THAN THE MAX ATTEMPT COUNT ";
                        //THE ATTEMPTS COUNT IS LESS THAN THE MAX COUNT
                        //increase the attack count
                        $new_count = $data[$username]['attempt'] + 1;
                        //if the max limit for attack has not reached
                        //get the old content
                        $old_content = $this->getAttemptsCount($ip);
                        $old_content[$username]['attempt'] = $new_count;
                        //update the count for the username
                        $result = $this->writeAttemptsInFile($ip, $old_content);
                        //also check for the timestamp if its older, then delete the content
                    }
                }
                else
                {
//                    echo "THE TIME HAS EXPIRED";
                    //THE TIMER HAS EXPIRED
                    //get the old content
                    $old_content = $this->getAttemptsCount($ip);
                    //reset
                    $old_content[$username]['attempt'] = 1;
                    $old_content[$username]['timestamp'] = $current_timestamp;
                    $result = $this->writeAttemptsInFile($ip, $old_content);
                    //RESET THE COUNT OF ATTEMPTS
                    //UPDATE THE FILE
                }
            }
        }
        return $result;
    }

    public function formatContent($username, $timestamp, $attempt)
    {
        $temp = array(
            $username => array(
                'timestamp' => $timestamp,
                'attempt' => $attempt,
            ),
        );
        return $temp;
    }

    public function preapreUpdatedContent($username,$timestamp, $attempt,$oldcontent)
    {
        $new_element = $this->formatContent($username,$timestamp, $attempt);
        $oldcontent[$username] = $new_element[$username];
        return $oldcontent;
    }


    //should be used the first time since we need to add php tags
    public function writeAttemptsInFile($ip, $content)
    {
        $filepath = OSE_WEBLOGFOLDER . ODS . $ip . ODS . 'bruteforceattempts.php';
        if(file_exists($filepath))
        {
            $flag_bf = true;
        }else{
            $flag_bf = false;
        }
        $filecontent = "<?php\n" . '$attempts = ' . var_export($content, true) . ";";
        $result = file_put_contents($filepath, $filecontent);
        if(!$flag_bf)
        {
            chmod($filepath,0777);
        }
        return ($result == false) ? false : true;
    }

    public function getAttemptsCount($ip)
    {
        $attempts = null;
        $filepath = OSE_WEBLOGFOLDER . ODS . $ip . ODS . 'bruteforceattempts.php';
        if (file_exists($filepath)) {
            require($filepath);
        }
        return $attempts;
    }

    public function getAttemptsCountforUsername($ip,$username)
    {
        $attempts = null;
        $filepath = OSE_WEBLOGFOLDER . ODS . $ip . ODS . 'bruteforceattempts.php';
        if (file_exists($filepath)) {
            require($filepath);
            return $attempts[$username]['attempt'];
        }
        return $attempts;
    }

    //return if the timer has expired or not
    public function timeKeeper($firsttimestamp, $currenttime,$timelimit)
    {
        $timediff  = $currenttime - $firsttimestamp;
        if($timediff <= ($timelimit*60))  // convert minutes into seconds
        {
            //still in the time frame and consider the no of attempts
            return true;
        }
        else {
            //not in the time frame the, count of attempts does not matter
            // so reset the count of attacks
         return false;
        }
    }

    public function isIpBlocked($ip)
    {
        $filepath = OSE_WEBLOGFOLDER.ODS.$ip.ODS."blocked.php";
        if(file_exists($filepath))
        {
            $attempt = $this->getAttemptFromLocalFiles($ip);
            //the ip has been blocked
            return true;
        }else {
            //the ip is not blocked
            return false;
        }
    }

    public function isIPBlockedFromDB($ip)
    {
        $result =  $this->ipmanagement->isIPBlockedDB($ip);
        if($result)
        {
            $this->showBanPage();
        }else {
            return false;
        }
    }

        ///FILE UPLOAD
    public function scanUploadFiles()
    {
        //get the list of allowed file extension types by users
        $this->getAllowExts();
        if (!empty ($this->allowExts)) {
            $scanResult = $this->checkFileTypes();
            return $scanResult;
        } else {
            //if the file type are not specified by the user
            return true;
        }
    }


    public  function getAllowExts()
    {
        $query = "SELECT `ext_name` FROM `#__osefirewall_fileuploadext` WHERE `ext_status` = 1";
        $this->db->setQuery($query);
        $results = $this->db->loadArrayList();
        $return = array();
        if (!empty($results)) {
            foreach ($results as $result) {
                $return[] = strtolower($result['ext_name']);
            }
        }
        $this->allowExts = (!empty($return)) ? $return : null;
    }


    public function checkFileTypes()
    {
        oseFirewallBase::callLibClass('uploadmanager','uploadmanager');
        $uploadmgr = new oseFirewallUploadManager();
        //return false if the file is safe
        //returns true if the user is banned or there was an error
        $subscription_status = oseFirewall::checkSubscriptionStatus(false);
        $score =100;
        $i = 0;
        if (!empty($_FILES)) {
            $file = $this->url;
            $file_headers = @get_headers($file);
            if (strpos($file_headers[0], '404')) {
                $exists = false;
            } else {
                $exists = true;
            }
            foreach ($_FILES as $file) {
                if (!empty ($file['tmp_name'])) {
                    if (is_array($file['tmp_name'])) {
                        $file['tmp_name'] = $file['tmp_name'][0];
                    }
                    if (!empty($file['tmp_name'])) {
                        $file['tmp_name'] = $this->cleanFileVariable($file['tmp_name']);
                        $file['type'] = $this->cleanFileVariable($file['type']);
                        $mimeType = $this->getMimeType($file);
                        $ext = explode('/', $file['type']);
                        if (is_array($file['name'])) {
                            $filename = $file['name'][$i];
                            $i++;
                        } else {
                            $filename =  $file['name'];
                        }
                        $info = new SplFileInfo($filename);
                        $extname = strtolower($info->getExtension());
                        $allowExts = array_map('trim', $this->allowExts);
                        if ($ext[1] == 'vnd.openxmlformats-officedocument.wordprocessingml.document') {
                            $ext[1] = $mimeType[1] = 'docx';
                        }
                        if ($ext[1] == 'vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
                            $ext[1] = $mimeType[1] = 'xls';
                        }
                        if ($ext[1] == 'jpg' && ($mimeType[1] == 'jpeg')) {
                            $ext[1] = 'jpeg';
                        }
                        if ($ext[1] == 'jpeg' && ($mimeType[1] == 'jpg')) {
                            $ext[1] = 'jpg';
                        }
                        if (($ext[1] == 'csv' || $ext[1] == 'comma-separated-values') && $mimeType[1] == 'plain') {
                            $ext[1] = $mimeType[1] = 'csv';
                        }
                        if ($ext[1] == 'download' && $mimeType[1] == 'zip') {
                            $ext[1] = $mimeType[1] = 'zip';
                        }
                        if ($ext[1] != $mimeType[1]) {
                            //if the mime type does not match
                            //malicious file deteceted
                            $uploadmgr->insertFileUploadLog($this->ip,$filename,$mimeType[1],2,0);
                            //prepare File Upload Log
                            $warningtext = "<br /> File Type: <b>" . $mimeType[1] . "</b> does not match the multimedia type ";
                            $warningtext_array = array($warningtext);
                            //record attack in the file
                            //delete the uplaoded files
                            if($subscription_status)
                            {
                                $score = $this->calcScore($this->ip,100);
                                $attempts = $this->calcAttempts($this->ip);
                                if($attempts<MAX_ATTEMP)
                                {
                                    $attempts = MAX_ATTEMP;
                                }
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }else{
                                $score = $this->calcScore($this->ip,10);
                                $attempts = $this->calcAttempts($this->ip);
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }

                            if($subscription_status == true)
                            {
                                $this->unlinkUPloadFiles();
                                $this->showBanPage();
                            }
                            return true;
                        } elseif ((!empty($extname) && (in_array($extname, $allowExts) == false)) || (!empty($ext[1])&& in_array($ext[1],$allowExts)==false)) {  ///score was set to  0
                            //if the type is not allowed
                            $uploadmgr->insertFileUploadLog($this->ip,$filename,$mimeType[1],1,0);
                            //prepare File Upload Log
                            $warningtext = "File Type: <b>" . $mimeType[1] . "</b> is not allowed by the user";
                            $warningtext_array = array($warningtext);
                            //record attack in the file
                            if($subscription_status)
                            {
                                $score = $this->calcScore($this->ip,100);
                                $attempts = $this->calcAttempts($this->ip);
                                if($attempts<MAX_ATTEMP)
                                {
                                    $attempts = MAX_ATTEMP;
                                }
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }else{
                                $score = $this->calcScore($this->ip,10);
                                $attempts = $this->calcAttempts($this->ip);
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }
                            //unlinke the uploaded file
                            if($subscription_status == true)
                            {
                                $this->unlinkUPloadFiles();
                                $this->showBanPage();
                            }
                            return true;
                        } else if (!$exists) {
                            $uploadmgr->insertFileUploadLog($this->ip,$filename,$mimeType[1],3,0);
                            //file is not uploaded
                            $warningtext = "<br /> Problems with the file header, File Type: <b>" . $mimeType[1] . "</b>";
                            $warningtext_array = array($warningtext);
                            if($subscription_status)
                            {
                                $score = $this->calcScore($this->ip,100);
                                $attempts = $this->calcAttempts($this->ip);
                                if($attempts<MAX_ATTEMP)
                                {
                                    $attempts = MAX_ATTEMP;
                                }
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }else{
                                $score = $this->calcScore($this->ip,10);
                                $attempts = $this->calcAttempts($this->ip);
                                $return = $this->logAttacks(array('13'),$warningtext_array,$_FILES,$attempts,$score);
                            }
                            //unlink the file
                            if($subscription_status == true)
                            {
                                if($subscription_status == true) {
                                    $this->unlinkUPloadFiles();
                                    $this->showBanPage();
                                }
                            }
                            return true;
                        } else
                        {
                            //the uploaded file is safe to use
                            $uploadmgr->insertFileUploadLog($this->ip,$filename,$mimeType[1],0,0);
                            $return = $this->prepareContinueMessage("The upload file type is safe to use ");
                            return false;
                        }
                    }
                }
                else {
                    $this->errorLog("Inconsistent File Type", 'The tmp_name variable is empty');
                        return true;
                }
            }
        }else {
            return true;
        }
    }

    protected function cleanFileVariable($fileVar)
    {
        if (is_array($fileVar)) {
            foreach ($fileVar as $filetmp) {
                $fileVar = $filetmp;
                break;
            }
        }
        return $fileVar;
    }

    protected function getMimeType($file)
    {
        $mimeType = $this->getFileInfo($file['tmp_name']);
        if (empty ($mimeType)) {
            $mimeType = $this->checkisPHPfile($file['tmp_name']);
        }
        if (!empty ($mimeType)) {
            if (strstr($mimeType, '/') != false) {
                $mimeType = explode("/", $mimeType);
            } else {
                $tmp = explode(" ", $mimeType);
                $mimeType = array();
                $mimeType[0] = strtolower($tmp [1]);
                $mimeType[1] = strtolower($tmp [0]);
            }
        } else {
            $mimeType = explode("/", $file['type']);
        }
        return $mimeType;
    }


    protected function getFileInfo($filename)
    {
        if (!defined('FILEINFO_MIME_TYPE')) {
            define('FILEINFO_MIME_TYPE', 1);
        }
        $defined_functions = get_defined_functions();
        if ((in_array('finfo_open', $defined_functions['internal'])) || function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $content_type = finfo_file($finfo, $filename);
            finfo_close($finfo);
            return $content_type;
        } elseif (function_exists('mime_content_type')) {
            $content_type = mime_content_type($filename);
            return $content_type;
        } else {
            return false;
        }
    }

    protected function checkisPHPfile($file)
    {
        if (empty($file)) {
            return false;
        }
        if (filesize($file) > '2048000') {
            return false;
        }
        $data = file($file);
        $data = implode("\r\n", $data);
        $pattern = "/(\<\?)|(\<\?php)/";
        if (preg_match($pattern, $data)) {
            return 'application/x-httpd-php';
        } else {
            return false;
        }
    }

    protected function unlinkUPloadFiles()
    {
        if (isset($_FILES['tmp_name']) && is_array($_FILES['tmp_name'])) {
            foreach ($_FILES['tmp_name'] as $filetmp) {
                if (file_exists($filetmp)) {
                    unlink($filetmp);
                }
                break;
            }
        } else {
            if (isset($_FILES['tmp_name']) && file_exists($_FILES['tmp_name'])) {
                unlink($_FILES['tmp_name']);
            }
        }
        unset ($_FILES);
    }

    protected function composeUploadLogResult($valStatus, $filename, $filetype)
    {
        $return['ip'] = $this->ip;
        $return['validation_status'] = $valStatus;
        $return['fileuploadlog'] = true;
        $return['file_name'] = $filename;
        $return['file_type'] = $filetype;
        $return['datetime'] = $this->getDateTime();
        return $return;
    }

    public function show403Msg($msg)
    {
        header('HTTP/1.1 403 Forbidden');
        $banbody = '<html>
						<head>
							<title>403 Forbidden</title>
						</head>
						<body>
						<div class="alert alert-danger alert-dismissible" role="alert">
                          <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                          <strong>Warning!</strong> ' . $msg . '
                        </div>
						</body>
					 </html>';
        echo $banbody;
        exit;
    }


    protected function getDateTime()
    {
        oseFirewall::loadDateClass();
        $time = new oseDatetime();
        return $time->getDateTime();
    }


    //anti virus to scan for the uploaded file
    // return true if the virus is detected
    //$scanUploadFilesResult -> previous scan results related to the type of the file
    //$filesarray -> content of the $_FILES
    public function scanFilesforVirus()
    {
        //return false if the file is safe
        //return true if the file has viruses or there was a errorOSE_VIRUSPATTERN_FILE
        //get the pattern list
        //get the content of file
        //call scanfile function
        oseFirewallBase::callLibClass('uploadmanager','uploadmanager');
        $uploadmgr = new oseFirewallUploadManager();
        if(!empty($_FILES)) {
            foreach ($_FILES as $file) {
                if (file_exists($file['tmp_name'])) {
                    oseFirewall::callLibClass('vsscanner', 'vsscanner');
                    $scanner = new virusScanner (); // call to the free class
                    $type = array(1, 2, 3, 4, 5, 6, 7, 8);
                    $scanner->generatePatternsFiles($type,true);
                    $pattern = $scanner->getVirusPatternsfromLocalFile(true);
                    $temp = $scanner->fileScan($file['tmp_name'], $pattern);
                    if ($temp == 1) {
                        $uploadmgr->updateFileUploadLog($this->ip,1,$file['name'],4);
                        $warningtext = "virus was detected in the file " . $file['tmp_name'];
                        $warningtext_array = array($warningtext);
                        $subscription_status = oseFirewallBase::checkSubscriptionStatus(false);
                        if($subscription_status)
                        {
                            $score = $this->calcScore($this->ip,100);
                            $attempts = $this->calcAttempts($this->ip);
                            if($attempts<MAX_ATTEMP)
                            {
                                $attempts = MAX_ATTEMP;
                            }
                            $result = $this->logAttacks(array('14'), $warningtext_array, $_FILES, $score, $attempts);

                        }else{
                            $score = $this->calcScore($this->ip,10);
                            $attempts = $this->calcAttempts($this->ip);
                            $result = $this->logAttacks(array('14'), $warningtext_array, $_FILES, $attempts, 10);
                        }
                        if ($result['status'] == 1) {
                            //malware was logged and the database was updated
                            $temp = $this->prepareSuccessMessage($warningtext);
                            if($subscription_status == true)
                            {
                                $this->unlinkUPloadFiles();
                                $this->showBanPage();
                            }
                            return true;
                        } else {
                            //error in logging the malware
                            $this->errorLog("Virus scan for upload files ", "Error in logging the attack");
                            return true;
                        }
                    }else {
                        $uploadmgr->updateFileUploadLog($this->ip,2,$file['name']);
                    }
                } else {
                    //file does not exists
                    $this->errorLog("Virus scan for upload files ", " File does not exists ");
                    return true;
                }
            }
            return false;
        }else {
            //file array is empty
            return true;
        }

    }

    //check for malicious user agents
    public function checkMUA() {
        // Some PHP binaries don't set the $_SERVER array under all platforms
        if (! isset ( $_SERVER )) {
            $this->errorLog("Check Malicious User Agent", "SERVER variable is not set");
            return true;
        }
        if (! is_array ( $_SERVER )) {
            $this->errorLog("Check Malicious User Agent", "SERVER variable is not an array");
            return true;
        }
        // Some user agents don't set a UA string at all
        if (! array_key_exists ( 'HTTP_USER_AGENT', $_SERVER )) {
            $this->errorLog("Check Malicious User Agent", "HTTP_USER_AGENT is not set");
            return true;
        }
        $mua = $_SERVER ['HTTP_USER_AGENT'];
        $detected = false;
        $patterns = '/archive\.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune/im';

        if(preg_match($patterns,$mua,$matches))
        {
            $detected = true;
        }
        unset ( $patterns );
        $return = array ();
        if ($detected == true)
        {
            if(is_array($matches))
            {
                $content = "Malicious User Agent : ".$matches[0];
            }else
            {
                $content = "Malicious User Agent : ".$matches;
            }
            $subscription_status = oseFirewall::checkSubscriptionStatus(false);
            if($subscription_status)
            {
                $score = $this->calcScore($this->ip,100);
                $attempts = $this->calcAttempts($this->ip);
                if($attempts<MAX_ATTEMP)
                {
                    $attempts = MAX_ATTEMP;
                }
                $return =  $this->logAttacks(array('3'),array($content), array(),$attempts,$score);
            }else{
                $score = $this->calcScore($this->ip,10);
                $attempts = $this->calcAttempts($this->ip);
                $return =  $this->logAttacks(array('3'),array($content), array(),$attempts,$score);//set the attempt count to 10 straigth away
            }
            if($subscription_status == true)
            {
                $this->showBanPage();
            }
        }else {
            return true;
        }
    }

    //return a pattern consisting of the the allowed bots
    public function getAllowedBots($settings)
    {
        $pattern = array();
            if(!empty($settings[22]) && $settings[22] == 1)
            {
                array_push($pattern,'googlebot');
            }
            if(!empty($settings[23]) && $settings[23] == 1)
            {
                array_push($pattern,'yahoobot');
            }
            if(!empty($settings[24]) && $settings[24] == 1)
            {
                array_push($pattern,'msnbot');
            }
        if(!empty($pattern))
        {
            $temp = implode('|',$pattern);
            $final_pattern = "/".$temp."/im";
            return $final_pattern;
        }else {
            //if setting is turned off returned empty pattern
            $pattern = '';
            return $pattern;
        }
    }

    //clean the name so that they can be used for string comparison
    public function cleanBotsNames($array)
    {
        $allowedbots = array();
        $pattern = "/google|msn|yahoo/im";
        $i = 0;
        foreach($array as $element)
        {
            if(preg_match($pattern,$element,$matches))
            {
               $allowedbots[$i] = $matches[0];
                $i ++;
            }
        }
        return $allowedbots;
    }

    public function preaprePatternFromAllowedBots($allowedbots)
    {
        $pattern = null;
        $len = count($allowedbots);
        for($i = 0; $i<$len;$i++)
        {
            if($i == 0)
            {
                $pattern= "/".$allowedbots[$i];
            }
            if($i = ($len-1))
            {
                $pattern =$pattern."|".$allowedbots[$i]."/im";
            }
            else {
                $pattern =$pattern."|".$allowedbots[$i];
            }
        }
        return $pattern;
    }

    //return true if the bot is one of the user selected bots
    public function isAllowedBot($pattern)
    {
        if (!empty($_SERVER['HTTP_USER_AGENT'])) {
            if (preg_match($pattern, $_SERVER['HTTP_USER_AGENT'], $match)) {
                $temp = $this->prepareSuccessMessage("The detected search engine bot is :".$match[0]);  //status == 1
                return $temp;
            } else {
                $temp = $this->prepareContinueMessage("No search engine bot was found ");  // status ==2
                return $temp;
            }
        } else {
            //user agent is not set
            $this->errorLog("Check Malciious User Agents", "The HTTP_USER_AGENT variable is not set ");
            return $this->prepareSuccessMessage("TThe HTTP_USER_AGENT variable is not set Continue");
        }
    }

    //check if the user agent of the request needs to be monitored
    //return true if it needs to be monitored
    public function monitorBots($settings)
    {
        $isabot = $this->isASearchEngineBot();
        if(!$isabot)
        {
            return true;
        }else {
            $allowedbotPattern = $this->getAllowedBots($settings); //gets the list of user selected bots from the user
            //check the patterns with the server variables to detect the bot
            if(empty($allowedbotPattern))
            {
                //it is a search engine bot but the user does not wants to scan it
                return false;
            }
            $result = $this->isAllowedBot($allowedbotPattern);
        if($result['status'] == 1)
        {
            //bot was detecetd
            return true;
        }
        else
        {
            //bot is not selected
            return false;
        }
        }
    }

    public function isASearchEngineBot()
    {
        $pattern = "/google|msn|yahoo/im";
        if (preg_match($pattern, $_SERVER['HTTP_USER_AGENT'], $match))
        {
            return true;
        }else {
            return false;
        }

    }

    public function checkIsSet($array,$field,$value)
    {
        if(isset($array[$field]))
        {
            if($array[$field] == $value)
            {
                return true;
            }else{
                return false;
            }
        }else {
            return false;
        }
    }

    public function errorLog($method, $message)
    {
        //if file exists
        if(file_exists(OSE_FWSCANNERV7_ERRORLOG))
        {
            //get the old content
            $oldcontent = $this->getErrorLogContent();
            if(!empty($oldcontent) && count($oldcontent)>100)
            {
                $temp_content = $this->removeOlderErrorLog($oldcontent);
                unset($oldcontent);
                $oldcontent = $temp_content;
            }
            $newcontet = $this->prepareContent($method, $message);
            array_push($oldcontent,$newcontet);
            //append the new one
            //write the content
            $this->writeErrorLog($oldcontent);
        }else {
            $content = $this->formatContentErrorLog($method,$message);
            $this->writeErrorLog($content);
        }
    }

    public function removeOlderErrorLog($temp_log)
    {
        return array_splice($temp_log,-100);
    }
    public function prepareContent($methodname, $message)
    {
        $temp = array(
                'ip' => $this->ip,
                'methodname' =>$methodname,
                'message' => $message,
                'datetime' => date('Y-m-d h:i:s'),
        );
        return $temp;
    }
    public function formatContentErrorLog($methodname, $message)
    {
        $temp = array(
            array(
            'ip' => $this->ip,
            'methodname' =>$methodname,
            'message' => $message,
            'datetime' => date('Y-m-d h:i:s'),
        ),
    );
        return $temp;
    }

    public function writeErrorLog($content)
    {
        if(!file_exists(OSE_WEBLOGFOLDER))
        {
            $this->makeDirs(OSE_WEBLOGFOLDER,0777,true);
        }
        $filecontent = "<?php\n" . '$log = ' . var_export($content, true) . ";";
        if(file_exists(OSE_FWSCANNERV7_ERRORLOG))
        {
            $flag_errorlog = true;
        }else{
            $flag_errorlog = false;
        }
        $result = file_put_contents(OSE_FWSCANNERV7_ERRORLOG, $filecontent);
        if(!$flag_errorlog)
        {
            chmod(OSE_FWSCANNERV7_ERRORLOG,0777);

        }
        return ($result == false) ? false : true;
    }
    public function getErrorLogContent()
    {
        $log = array();
        if(file_exists((OSE_FWSCANNERV7_ERRORLOG)))
        {
            require(OSE_FWSCANNERV7_ERRORLOG);
        }
        return $log;
    }

    //scan the requests for vrious attacks and keeps a log of all the attacks
    public function scanTraffic($settings,$type)
    {
        $this->loadLibrary();
        //check the country status
         $countryblock_reesult= $this->checkCountryStatus_v7();
        if($countryblock_reesult == true)
        {
            //the country has been white listed
            //do not scan the requests
            return true;
        }
        //CHECK IF THE IP IS MARKED AS SPAM FROM THE STOP FORUM SPAN API
        $this->isIPBlockedFromDB($this->ip);
        $isWhiteListed = $this->ipmanagement->isIPWhiteListedDB($this->ip);
        $isWhiteListedLocalFile = $this->ipmanagement->checkIpIsWhiteListedLocalFile($this->ip);
        if($isWhiteListed || $isWhiteListedLocalFile)
        {
            return true;
        }
        if ($settings[11] == 1) {
            $this->antispamProtection();
        }
        //CHECK IF THE USER AGENT IS MALICIOUS OR NOT
        if ($settings[16] == 1)  // continue status  == 2 ; attacked log  == 1  and error in the operation  == 0
        {
            //CHECK IF ITS A MALICIOUS BOT
            $this->checkMUA();
        }
        $seosettings = $this->getSeoConfiguration();
        $result_monitobots = true;
        //CHECK THE BOTS
        if ($seosettings['info'][22] == 1 || $seosettings['info'][23] == 1 || $seosettings['info'][24] == 1) {
            $result_monitobots = $this->monitorBots($seosettings['info']);
        }
        if (!$result_monitobots) {
            //exit the scanning if the result is false
            //if its not the search engine bot or if its not selected
            return;
        }
        if ($settings[13] == 1) {
            $this->scanUploadFiles();
        }
        if ($settings[14] == 1) {
            $this->scanFilesforVirus();
        }
        $result_reqscan = false;
        if ($settings[2] == 1 || $settings[3] == 1 || $settings[4] == 1 || $settings[5] == 1 || $settings[6] == 1 || $settings[8] == 1 || $settings[10] == 1 || $settings[12] == 1) {
            $result_reqscan = $this->fwscannerv7($settings,$type);
        }
        if ($result_reqscan == true) {
            return ;
        }
    }


    protected function checkCountryStatus_v7()
    {
        oseFirewallBase::callLibClass('fwscanner','fwscannerbs');
        $fs = new oseFirewallScannerBasic();
        $result = $fs->countryCheckV7();
        return $result;
    }
    public function showBanPage()
    {
        $data = $this->getCompleteFirewallSettingsFromDb();
        if($data['info'][30] == 0)
        {
            if(oseFirewallBase::isSuite())
            {
                $this->show403Page_suite($data);
            }else{
                $this->show403Page($data);
            }
        }else {
            if(isset($data['info'][32]) && !empty($data['info'][32]))
            {
                $this->customRedirect($data['info'][32]);
            }else{
                $webmaster = $data['info'][7];
                $adminEmail = (isset ($webmaster)) ? $webmaster : DEFAULT_CONTACT_ADDRESS;
                $customBanPage = (!empty ($data['info'][31])) ? $data['info'][31] : 'Banned';
                $pageTitle = (!empty ($data['info'][18])) ? $data['info'][18] : 'Centrora Security';
                $metaKeys = (!empty ($data['info'][19])) ? $data['info'][19] : 'Centrora Security';
                $metaDescription = (!empty ($data['info'][20])) ? $data['info'][20] : 'Centrora Security';
                $metaGenerator = (!empty ($data['info'][21])) ? $data['info'][21] : 'Centrora Security';
                if (isset($data['info'][28]) && $data['info'][28] == 1) {
                    $ga['status'] = 1;
                    $ga['secretkey'] = $data['info'][29];
                } else {
                    $ga['status'] = 0;
                }
                if(oseFirewallBase::isSuite())
                {
                    $banhtml = $this->getBanPage_suite($adminEmail, $pageTitle, $metaKeys, $metaDescription, $metaGenerator, $customBanPage, $ga);

                }else{
                    $banhtml = $this->getBanPage($adminEmail, $pageTitle, $metaKeys, $metaDescription, $metaGenerator, $customBanPage, $ga);

                }
                echo $banhtml;
                $this->db->closeDBO();
                exit;
            }

        }
    }


    protected function show403Page($data)
    {
        $webmaster = $data['info'][7];
        $adminEmail = (isset ($webmaster)) ? $webmaster : DEFAULT_CONTACT_ADDRESS;
        $customBanPage = (!empty ($data['info'][31])) ? $data['info'][31] : 'Banned';
        if (isset($data['info'][28]) && $data['info'][28] == 1) {
            $ga['status'] = 1;
            $ga['secretkey'] = $data['info'][29];
        } else {
            $ga['status'] = 0;
        }
        $banbody = $this->getBanPageBody($customBanPage, $adminEmail,$ga);
        header('HTTP/1.0 403 Forbidden');
        $banbody = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
					<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
						<head>
							<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
							<title>403 Forbidden</title>
							<link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/bootstrap.min.css">
         				<link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/blockpage.css">
                        <link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/animate.css">
						<script src="' . OSE_BANPAGE_ADMIN . '/public/js/jquery-1.11.1.min.js"></script>
						<script src="' . OSE_BANPAGE_ADMIN . '/public/js/plugins/wow/wow.min.js"></script>
						<script>new WOW().init();</script>
						<script>
      jQuery(document).ready(function($){
           $("#googleAuth-form").submit(function() {
             var data = $("#googleAuth-form").serialize();
             $.ajax({
             url: "index.php?",
            type: "POST",
            data: data,
            success: function(data)
            {
                if (data == 1)
                {
                   location.reload(true);
                }
                else
                {
                   alert("wrong code, try again");
                }
            }
        });
       return false; // avoid to execute the actual submit of the form.
});
})
                      </script>
						</head>
						<body>
								' . $banbody . '
						</body>
					 </html>';
        echo $banbody;
        $this->db->closeDBO();
        exit;
    }

    protected function show403Page_suite($data)
    {
        $webmaster = $data['info'][7];
        $adminEmail = (isset ($webmaster)) ? $webmaster : DEFAULT_CONTACT_ADDRESS;
        $customBanPage = (!empty ($data['info'][31])) ? $data['info'][31] : 'Banned';
        if (isset($data['info'][28]) && $data['info'][28] == 1) {
            $ga['status'] = 1;
            $ga['secretkey'] = $data['info'][29];
        } else {
            $ga['status'] = 0;
        }
        $banbody = $this->getBanPageBody($customBanPage, $adminEmail,$ga);
        $temp_domain = oseFirewallBase::getRegisteredWebsiteDomain();
        if(empty($temp_domain))
        {
         $domain =OSE_BANPAGE_ADMIN;
        }else{
            $http = ($temp_domain['protocol']==1)?"https":"http";
            $domain = $http."://".$temp_domain['domain'];
        }
        header('HTTP/1.0 403 Forbidden');
        $banbody = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
					<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
						<head>
							<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
							<title>403 Forbidden</title>
							<link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/bootstrap.min.css"">
         				<link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/blockpage.css">
                        <link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/animate.css">
						</head>
						<body>
								' . $banbody . '
						</body>
					 </html>';
        echo $banbody;
        $this->db->closeDBO();
        exit;
    }

    protected function customRedirect($custom_url)
    {
        if (!empty($custom_url)) {
            header('Location: ' . $custom_url);
            exit;
        }
    }

    protected function getBanPage($adminEmail, $pageTitle, $metaKeys, $metaDescription, $metaGenerator, $customBanPage,$googlAuthBanPage)
    {
        header('HTTP/1.0 403 Forbidden');
        $banbody = $this->getBanPageBody($customBanPage, $adminEmail,$googlAuthBanPage);
        $banhtml = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
					<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
						<head>
							  <meta http-equiv="content-type" content="text/html; charset=utf-8" />
							  <meta name="robots" content="index, follow" />
							  <meta name="keywords" content="' . $metaKeys . '" />
							  <meta name="description" content="' . $metaDescription . '" />
							  <meta name="generator" content="' . $metaGenerator . '" />
							  <title>' . $pageTitle . '</title>
          				<link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/bootstrap.min.css">
         				<link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/blockpage.css">
                        <link rel="stylesheet" href="' . OSE_BANPAGE_ADMIN . '/public/css/animate.css">
						<script src="' . OSE_BANPAGE_ADMIN . '/public/js/jquery-1.11.1.min.js"></script>
						<script src="' . OSE_BANPAGE_ADMIN . '/public/js/plugins/wow/wow.min.js"></script>
						<script>new WOW().init();</script>
						<script>
      jQuery(document).ready(function($){
           $("#googleAuth-form").submit(function() {
             var data = $("#googleAuth-form").serialize();
             $.ajax({
             url: "index.php?",
            type: "POST",
            data: data,
            success: function(data)
            {
                if (data == 1)
                {
                   location.reload(true);
                }
                else
                {
                   alert("firewall scanner v7 : wrong code, try again");
                }
            }
        });
       return false; // avoid to execute the actual submit of the form.
});
})
                      </script>
						</head>
						<body>
						' . $banbody . '
						</body>
					</html>';
        return $banhtml;
    }

    protected function getBanPage_suite($adminEmail, $pageTitle, $metaKeys, $metaDescription, $metaGenerator, $customBanPage,$googlAuthBanPage)
    {
        header('HTTP/1.0 403 Forbidden');
        $banbody = $this->getBanPageBody($customBanPage, $adminEmail,$googlAuthBanPage);
        $temp_domain = oseFirewallBase::getRegisteredWebsiteDomain();
        if(empty($temp_domain))
        {
            $domain =OSE_BANPAGE_ADMIN;
        }else{
            $http = ($temp_domain['protocol']==1)?"https":"http";
            $domain = $http."://".$temp_domain['domain'];
        }
        $banhtml = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
					<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
						<head>
							  <meta http-equiv="content-type" content="text/html; charset=utf-8" />
							  <meta name="robots" content="index, follow" />
							  <meta name="keywords" content="' . $metaKeys . '" />
							  <meta name="description" content="' . $metaDescription . '" />
							  <meta name="generator" content="' . $metaGenerator . '" />
							  <title>' . $pageTitle . '</title>
          					<link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/bootstrap.min.css"">
         				<link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/blockpage.css">
                        <link rel="stylesheet" href="' . $domain . '/administrator/components/com_ose_firewall/public/css/animate.css">
						</head>
						<body>
						' . $banbody . '
						</body>
					</html>';
        return $banhtml;
    }

    protected function getBanPageBody($customBanPage, $adminEmail,$googlAuthBanPage)
    {
        $banhead = '<header>
        <div id="hero">
            <div class="container herocontent">
				 <h2 class="wow fadeInUp" data-wow-duration="2s" style="color:#fff; text-shadow: 1px 1px 2px #000000;" >Your IP Address Has Been Blocked.</h2>
                <h4 class="wow fadeInDown" data-wow-duration="3s" style="color:#fff; text-shadow: 1px 1px 2px #000000;">The firewall has flagged your IP address, but don\'t worry!</h4>
            </div>
        </div>
     </header>';
        $banfooter = '<footer>
        <div class="container">
          <p style="color:#fff;">' . $customBanPage . '</p>
            <div class="copyright"><!-- FOOTER COPYRIGHT START -->
                 <h3 style="color:#fff;">WHAT NOW?</h3>
                 <p style="color:#fff;">Your IP address is ' . $this->ip . '. If you believe this is an error, please contact the <a href="mailto:' . $adminEmail . '?Subject=Inquiry:%20Banned%20for%20suspicious%20hacking%20behaviour - IP: ' . $this->ip . ' - Violation"> Webmaster </a>';
        $centroraGA = ($googlAuthBanPage['status']==1) ? 1:0;
        $secret = (!empty($googlAuthBanPage['secretkey'])) ? $googlAuthBanPage['secretkey'] : false;
        if ($centroraGA == 1 && ($secret!==false)) {
            $banfooter .= $this->getGoogleAuthForm();
        }
        $banfooter .= '</p>
	            </div><!-- FOOTER COPYRIGHT END -->
	         </div>
	     </footer>';
        $banbody = $banhead . $banfooter;
        $banbody = str_replace('info@opensource-excellence.com', $adminEmail, $banbody);
        $banbody = str_replace('info@your-website.com', $adminEmail, $banbody);
        $banbody = str_replace('OSE Team', 'Management Team', $banbody);
        return $banbody;
    }


    public function getGoogleAuthForm()
    {
        return ' <form id = "googleAuth-form" class="form-horizontal group-border stripped" role="form" action="index.php?">
            <lable style="color:#fff" for="googleAuthCode" class="form-label form-label-left form-label-auto">' . 'If you have Unban Google Authenticator enabled and setup, please input your code here' . '</lable>
            <input  type="text" id="googleAuthCode" class="form-textbox"  name="googleAuthCode">
            <button type="submit" class="btn btn-default" id="save-button">Submit</button>
            </form>';
    }

    public function verifyLoginGAcode()
    {
        $settings = $this->getCompleteFirewallSettingsFromDb();
        $secret = $settings['info'][29];
        if (!empty($secret)) {
            require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
            $gauthenticator = new CentroraGoogleAuthenticator();
            $otp = trim($_POST ['googleAuthCode']);
            require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_base32.php');
            $match = $gauthenticator->verify($secret, $otp);
            return $match;
        } else {
            return false;
        }
    }

    public function manageBanAdmins()
    {
        $flag = $this->verifyLoginGAcode();
        if ($flag == true) {
            oseFirewall::callLibClass('fwscannerv7','ipManagement');
            $this->ipmanagement = new ipManagement();
            $this->ipmanagement->monitorIp($this->ip);
            print_r(1);
            exit;
        } else {
            print_r(0);
            exit;
        }
    }


    /*
     * BAN PAGE MANAGEMENT CODE
     */

    //get ban page configuration
    public function getBanSettingsfromDb()
    {
        $settings  = array();
        $query = "SELECT `id`,`value` FROM `#__osefirewall_fwscannerv7Config` WHERE `type` = 'bruteforce'";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        if(!empty($temp))
        {
            foreach($temp as $record)
            {
                $settings[$record['id']] = $record['value'];
            }
        }
        if(!empty($settings))
        {
            $result['status'] = 1;
            $result['info'] = $settings;
            return $result;
        }else {
            $result['status'] = 0;
            $result['info'] = "The firewall scanner has not been set yet";
            return $result;
        }
    }

    public function showGoogleSecret()
    {
        require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
        $gauthenticator = new CentroraGoogleAuthenticator();
        $googleAuth = $this->getBanSettingsfromDb();
        if (empty($googleAuth['info'][28])) {
            $secret = $gauthenticator->create_secret();
            $QRcode = $gauthenticator->get_qrcode($secret);
        } else {
            $secret = $googleAuth['info'][29];
            $QRcode = $gauthenticator->get_qrcode($secret);
        }
        $this->updateGoogleAutneticationSecretKeyInDb($secret);
        $result = array(
            'secret' => "<input name=\"GA_secret\" id=\"GA_secret\" value=\"{$secret}\" readonly=\"readonly\"  type=\"text\" size=\"25\" />",
            'QRcode' => $QRcode
        );
        return $result;
    }

    //update the secret key for the ban page
    public function updateGoogleAutneticationSecretKeyInDb($key)
    {
        $vararray = array(
            'value'=>$key,
        );
        $result = $this->db->addData('update', '#__osefirewall_fwscannerv7Config', 'id',29, $vararray);
        $this->db->closeDBO ();
        return $result;
    }

    public function saveBanPageSettings($data)
    {
      $validate =  $this->validateBanPageInput($data[32],$data[31]);
      if($validate['status'] == 1)
      {
         if($data[30] ==1 )
         {
             $result1 = $this->updateSettings(30,$data[30]);
             if($result1 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 30");
             $result2 = $this->updateSettings(31,$data[31]);
             if($result2 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 31");
             $result3 =$this->updateSettings(32,$data[32]);
             if($result3 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 32");

         }else {
             $result1 = $this->updateSettings(30,$data[30]);
             if($result1 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 30");
         }
             $result4 = $this->updateSettings(28, $data[28]);
             if ($result4 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 28");
             $result5 = $this->updateSettings(29, $data[29]);
             if ($result5 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 29");
            if(OSE_CMS == "joomla" && (!oseFirewallBase::isSuite()))
            {
                $validateSecureKey = $this->validateSecureKey($data[34]);
                if($validateSecureKey['status']==0)
                 {
                     return $validateSecureKey;
                 }else{
                    if(!$this->secureKeyRecordExists())
                    {
                       $result6 = $this->insertSettings(34,$data[34]);
                    }else{
                        $result6 = $this->updateSettings(34, $data[34]);

                    }
                     if ($result6 == 0) return $this->prepareErrorMessage("There was a problem in updating the ban page settings for id 33");
                 }
            }else{
                 $this->updateSettings(34,0);
            }
          return $this->prepareSuccessMessage("The settings have been saved successfully");
     }else {
         return $validate;
     }
    }

    public function secureKeyRecordExists()
    {
        $query = "SELECT `id`,`value` FROM `#__osefirewall_fwscannerv7Config` WHERE `key` = 'secureKey'";
        $this->db->setQuery($query);
        $result = $this->db->loadObject();
        if(empty($result))
        {
            return false;
        }else{
            return true;
        }
    }

    public function validateSecureKey($secureKey)
    {
        if(!empty($secureKey)){
        $pattern = "/^[a-zA-Z\d]+$/";
        if (!preg_match($pattern, $secureKey)) {
            return oseFirewallBase::prepareErrorMessage('Backend Access Secure Key can only contain numbers, letters');
        } else{
            return oseFirewallBase::prepareSuccessMessage("Valida Access Secure Key");
        }
        }else{
            return oseFirewallBase::prepareSuccessMessage("Valida Access Secure Key");
        }
    }

    public function validateBanPageInput($url,$content)
    {
        if(!empty($url)) {
            if($url == 0 )
            {
                return $this->prepareSuccessMessage("The content and url has been validated ");
            }else  if (filter_var($url, FILTER_VALIDATE_URL) === false) {
                return $this->prepareErrorMessage("The URL is invalid");
            }
        }
        return $this->prepareSuccessMessage("The content and url has been validated ");
    }


    public function isGoogleAuthenticatorLoginEnabled()
    {
        $settings = $this->getCompleteFirewallSettingsFromDb();
        if(isset($settings['info'][27]) && $settings['info'][27] ==1)
        {
            return true;
        }else {
            return false;
        }
    }

    public function enableGoogleAuthenticationLogin()
    {
        require_once(OSE_FWFRAMEWORK.ODS.'googleAuthenticator'.ODS.'class_gauthenticator.php');
        if($this->isGoogleAuthenticatorLoginEnabled())
        {
            $gauthenticator = new CentroraGoogleAuthenticator();
            add_action('init', array($gauthenticator, 'init'));
        }
    }

    public function getLoginQRCode()
    {
        if (OSE_CMS == 'wordpress') {
            //googleauthenticator_secret
            $isgoogleAuthEnabled = $this->isGoogleAuthLoginActivated();
            if ($isgoogleAuthEnabled['status'] == 1) {
                $query = "SELECT * FROM `wp_usermeta` WHERE `meta_key` = 'googleauthenticator_secret'";
                $this->db->setQuery($query);
                $result = $this->db->loadObject();
                if (!empty($result)) {
                    if (isset($result->meta_value) && !empty($result->meta_value)) {
                        require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
                        $gauthenticator = new CentroraGoogleAuthenticator();
                        $QRcode = $gauthenticator->get_qrcode($result->meta_value);
                        $result1['status'] = 1;
                        $result1['qrcode'] = $QRcode;
                        return $result1;
                    } else {
                        return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                    }
                } else {
                    return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                }
            }else {
                return $isgoogleAuthEnabled;
            }
        }else if(OSE_CMS == 'joomla') {
            $isgoogleAuthEnabled = $this->isGoogleAuthLoginActivated();
            if ($isgoogleAuthEnabled['status'] == 1) {
                $secretkey = $this->getJoomlaGoogleAuthLoginSecretCode();
                if($secretkey['status'] == 1)
                {
                    require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
                    $gauthenticator = new CentroraGoogleAuthenticator();
                    $QRcode = $gauthenticator->get_qrcode($secretkey['info']);
                    $result1['status'] = 1;
                    $result1['qrcode'] = $QRcode;
                    return $result1;
                }else {
                    return $secretkey;
                }
            }else {
                return $isgoogleAuthEnabled;
            }
        }
    }

    public function getJoomlaGoogleAuthLoginSecretCode()
    {
        $query = "SELECT `id` FROM `#__users` WHERE `name` = 'Super User'";
        $this->db->setQuery($query);
        $result = $this->db->loadObject();
        if(!empty($result))
        {
            require_once JPATH_ADMINISTRATOR . '/components/com_users/models/user.php';
            $user = new UsersModelUser();
            $result1 = $user->getOtpConfig($result->id);
            if(empty($result1) || !isset($result1->config['code']))
            {
                $temp['status'] = 0;
                $temp['info'] = 'There was some problem in accessing the google authentication code of the superuser';
                return $temp;
            }else {
                $temp['status'] = 1;
                $temp['info'] = (string)$result1->config['code'];
                return $temp;
            }
        }else {
            $temp['status'] = 0;
            $temp['info'] = 'There was some problem in accessing the key of the superuser';
            return $temp;
        }
    }

    //return the google authentication secret key and the the qr code
    public function getLoginGAuthKeyandCode()
    {
        if (OSE_CMS == 'wordpress') {
            //googleauthenticator_secret
            $isgoogleAuthEnabled = $this->isGoogleAuthLoginActivated();
            if ($isgoogleAuthEnabled['status'] == 1) {
                $query = "SELECT * FROM `wp_usermeta` WHERE `meta_key` = 'googleauthenticator_secret'";
                $this->db->setQuery($query);
                $result = $this->db->loadObject();
                if (!empty($result)) {
                    if (isset($result->meta_value) && !empty($result->meta_value)) {
                        require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
                        $gauthenticator = new CentroraGoogleAuthenticator();
                        $QRcode = $gauthenticator->get_qrcode($result->meta_value);
                        $result1['status'] = 1;
                        $result1['qrcode'] = $QRcode;
                        $result1['secretKey'] = $result->meta_value;
                        return $result1;
                    } else {
                        return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                    }
                } else {
                    return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                }
            }else {
                return $isgoogleAuthEnabled;
            }
        }
        if(OSE_CMS == 'joomla')
        {
            $isgoogleAuthEnabled = $this->isGoogleAuthLoginActivated();
            if ($isgoogleAuthEnabled['status'] == 1) {
                $secretkey = $this->getJoomlaGoogleAuthLoginSecretCode();
                if($secretkey['status'] == 1)
                {
                    require_once(OSE_FWFRAMEWORK . ODS . 'googleAuthenticator' . ODS . 'class_gauthenticator.php');
                    $gauthenticator = new CentroraGoogleAuthenticator();
                    $QRcode = $gauthenticator->get_qrcode($secretkey['info']);
                    $result1['status'] = 1;
                    $result1['qrcode'] = $QRcode;
                    $result1['secretKey'] = $secretkey['info'];
                    return $result1;
                }else {
                    return $secretkey;
                }
            }else {
                return $isgoogleAuthEnabled;
            }
        }
    }
    public function isGoogleAuthLoginActivated()
    {
        if (OSE_CMS == 'wordpress') {
            $query = "SELECT * FROM `wp_usermeta` WHERE `meta_key` = 'googleauthenticator_enabled'";
            $this->db->setQuery($query);
            $result = $this->db->loadObject();
            if (!empty($result)) {
                if (isset($result->meta_value) && ($result->meta_value == 'enabled')) {
                    return $this->prepareSuccessMessage("The google Auth has been enabled ");
                }else {
                    return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                }
            }else {
                return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
            }
        }else if(OSE_CMS == 'joomla')
         {
            $query = "SELECT `enabled` FROM `#__extensions` WHERE `name` = 'plg_twofactorauth_totp' AND `folder` = 'twofactorauth'";
            $this->db->setQuery($query);
            $result = $this->db->loadObject();
            if(!empty($result))
            {
                if($result->enabled == 1)
                {
                    return $this->prepareSuccessMessage("The google Auth has been enabled ");
                }else {
                    return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
                }
            }else {
                return $this->prepareErrorMessage("The google authentication has not been set please click on the activate box on the user page to use this service ");
            }
        }
    }

    public function penetrationTestingResponse()
    {
        header('HTTP/1.0 403 Forbidden');
        die(json_encode(array("status" =>"forbidden","PatternId" =>$this->patternId)));
    }
    public function penetrationTestingSucessResponse($msg = null)
    {
        header('HTTP/1.0 200 Success');
        die(json_encode(array("status" =>"success",'Message' =>$msg)));
    }

    public function toggleFirewallScannerV7($value)
    {
        if($value ==1)
        {
            $result = $this->updateSettings(1,1);
            if($result == 0)
            {
             return $this->prepareErrorMessage('There was some problem in turning the Firewall Scanner V7 ON');
            }else {
                return $this->prepareSuccessMessage('The Firewall Scanner V7 has been Turned ON');
            }
        }else {
           $result =  $this->updateSettings(1,0);
            if($result == 0)
            {
                return  $this->prepareErrorMessage('There was some problem in turning the Firewall Scanner V7 OFF');
            }else {
                return  $this->prepareSuccessMessage('The Firewall Scanner V7 has been Turned OFF');
            }
        }
    }

    public function toggleFirewallScanner($value)
    {
        oseFirewall::callLibClass('fwscanner','fwscanner');
        $fs = new oseFirewallScanner();
        //value ==1 ===> turn on firewall scanner 7
        if($value == 1)
        {
         $fs7 = $this->toggleFirewallScannerV7(1);
         if($fs7['status'] == 1)
         {
           $fs6 = $fs->toggleFirewallScanerV6(1);
             if($fs6['status'] == 1)
             {
                 $result = $this->prepareSuccessMessage('Firewall Scanner V7 has been activated Successfully');
                 if(OSE_CMS =='wordpress')
                 {
                     $result['url'] = '?page=ose_fw_bsconfigv7';
                 }else {
                     $result['url'] = '?option=com_ose_firewall&view=bsconfigv7';
                 }
                 return $result;
             }
         }else {
             //error in turning on the firewall scanner v7
             return $fs7;
         }

        }else {
            //turn off the firewall scanner v7
            //turn on v6
            $fs6 = $fs->toggleFirewallScanerV6(0);
            if($fs6['status'] == 1)
            {
                $fs7 = $this->toggleFirewallScannerV7(0);
                if($fs7['status'] == 1)
                {       //v6 on and v7 off
                    $result = $this->prepareSuccessMessage('Firewall Scanner V6 has been activated Successfully');
                    if(OSE_CMS =='wordpress')
                    {
                        $result['url'] = '?page=ose_fw_bsconfig';
                    }else {
                        $result['url'] = '?option=com_ose_firewall&view=bsconfig';
                    }
                    return $result;
                }
            }else {
                //error in turning on the firewall scanner v6
                return $fs6;
            }
        }
    }

    public function getFirewallScannerVersion()
    {
        $fs7 = $this->getFirewallSettingsfromDb();
        $fs6 = oseFirewall::getConfiguration('scan');
        $result =array();
        if($fs7['status'] == 1)
        {
            $result['status'] = 1;
            $result['v7'] =$fs7['info'][1];
        }
        if($fs6['success']==1)
        {
            $result['status'] = 1;
            $result['v6'] = $fs6['data']['devMode'];
        }
        return $result;

    }

    //code to manage the advanced rules pattern version

    /*
    * UPDATE THE ADVANCE RULES DATABASE FOR BOTH THE FREE USERS AND THE PREMIUM USERS
    * TYPE :
    * 1=>IF ADV RULES DB IS NOT EMPTY
    * 0=> IF THE ADV RULES DB IS EMPTY
    */
    public function updateLocalFile()
    {
        $settings = $this->getFirewallSettingsfromDb();
        $temp = $this->updateLocalFiles($settings['info']);
        if($temp['status'] == 1)
        {
            return oseFirewallBase::prepareCustomMessage(1,'The Firewall Rules has been updated successfully');
        }else {
            //error in updating the local files
            return $temp;
        }
    }

    //cron job to dlete the expired web logs as well as delete the old records for the ip table
    private function toggleManageWebLogCronJobs($enabled)
    {
        if(!oseFirewallBase::checkSubscriptionStatus(false))
        {
            return true;
        }
        $custweekdays = Array(0,1,2,3,4,5,6);
        $result['custweekdays'] = base64_encode(oseJSON::encode($custweekdays));
        date_default_timezone_set('Australia/Melbourne');
        $time = date("H.i", time());
        $custhours  =  ceil($time);
        $result['custhours'] =$custhours;
        oseFirewall::callLibClass('panel','panel');
        $panel = new panel();
        //tyoe no =>6;
        //cloudbackuptype = 1
        //gitbackup frequency = null
        $panel->saveCronConfigEmailStats($result['custhours'], $result['custweekdays'], 6, 1, $enabled, 1,true);
    }
}


