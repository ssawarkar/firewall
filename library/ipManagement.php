<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 6/07/2016
 * Time: 1:42 PM
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
class ipManagement{
    private  $iptable = '#__osefirewall_ipmanagement';
    private $orderBy = null;
    private $limitStm = null;
    private $where = null;

    public function __construct($qatest = false)
    {
        $this->qatest = $qatest;
        $this->db = oseFirewall::getDBO();
        $this->prerequisistes();
    }
    public function prerequisistes()
    {
//        $iptable = '#__osefirewall_ipmanagement';
        $iptableexists = $this->db->isTableExists($this->iptable);
        if (!$iptableexists) {
            //if the ip table does not exist
            oseFirewallBase::createBlockIpTable($this->db);
        }
        oseFirewall::callLibClass('fwscannerv7','fwscannerv7');
        $this->fwscanner = new oseFirewallScannerV7();
    }

    //add the blocked ip to the database table
    public function addBlockedIp($ip)
    {
        $ipexistsindb = $this->checkIfIPalreadyexistsInDB($ip);
        if (empty($ipexistsindb)) {
            $varValues = array(
                'ip' => $ip,
                'status' => 2,
                'ischecked' =>0,
                'isspam' =>0,
                'lastchecked' =>0,
                'datetime'=> date('Y-m-d h:i:s'),
            );
            $result = $this->db->addData('insert', '#__osefirewall_ipmanagement', '', '', $varValues);
        } else {
            //ip exists change status to blacklisted
            $varValues = array(
                'status' => 2,
                'datetime'=> date('Y-m-d h:i:s'),
            );
            $result = $this->db->addData('update', '#__osefirewall_ipmanagement', 'ip', $ip, $varValues);
        }
        if($result !== 0)
        {
            return  $this->fwscanner->prepareSuccessMessage("The ip has been added to the black list");
        }
        else {
            return  $this->fwscanner->prepareErrorMessage("There was some problem in adding the ip to the black list");
        }
    }

   /*
    * $array = list of ids
    * $status status that needs to be changed to
    */
    public function changeStatusofIp($array,$status)
    {
        foreach($array as $record)
        {
            //if there is any ip corresponding to the id
            $temp = $this->getIpFromDb($record);
            //if the ip does not exist it will return emptry array
            if(!empty($temp)) {
                //access the ip fiels od the returned  record
                $ip = $temp->ip;
                $date = new DateTime();
                $current_timestamp = $date->getTimestamp();
                if($status == 1) {
                    $varValues = array(
                        'status' => $status,
                        'ischecked' => (int)1,
                        'isspam' => (int)0,
                        'lastchecked' => $current_timestamp,
                        'datetime' => date('Y-m-d h:i:s'),
                    );
                }
                else {
                    $varValues = array(
                        'status' => $status,
                        'datetime' => date('Y-m-d h:i:s')
                    );
                }
                //update the db table
                $result = $this->db->addData('update', '#__osefirewall_ipmanagement', 'ip', $ip, $varValues);
                if($status == 1 && $result!== 0)
                {
                    $this->deleletIpFromTempFile($ip);
                    $this->rmdir_recursive(OSE_WEBLOGFOLDER.ODS.$ip);
                }
                if ($result == 0) {
                    return $this->fwscanner->prepareErrorMessage("There was some problem in adding the ip to the" . $this->getListName($status) . " list");
                }
            }
            else {
                return $this->fwscanner->prepareErrorMessage("There Ip with the provided id does not exist");
            }
        }
        if($status ==1 )
        {
            $this->updateEmailNotificationFile($array);
        }
        return  $this->fwscanner->prepareSuccessMessage("The records have been updated successfully");
    }

    //return the record with the matfching id
    public function getIpFromDb($id)
    {
        $query = "SELECT `ip` FROM `#__osefirewall_ipmanagement` WHERE `id`=" . $this->db->quoteValue($id);
        $this->db->setQuery($query);
        $result = $this->db->loadObject();
        return $result;
    }


    //get the name of list
    //used to set the return messages
    public function getListName($status)
    {
        if($status == 0)
        {
            return 'Monitor';
        }else if($status == 1)
        {
            return 'White';
        }elseif($status == 2)
        {
            return 'Black';
        }
    }

    //to check if the entry for the ip exists in the database
    public function checkIfIPalreadyexistsInDB($ip)
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `ip`=" . $this->db->quoteValue($ip);
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }

    //public function return a list of blocked ips   => status == 2
    public function getBlockedIps()
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `status`= 2";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }

    //check the db record for the ip if its blocked
    public function isIPBlockedDB($ip)
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `status`= 2 AND `ip` = '".$ip."'";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return (!empty($result)) ? true : false;
    }

    //check if an ip is whitelisted
    public function isIPWhiteListedDB($ip)
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `status`= 1 AND `ip` = '".$ip."'";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return (!empty($result)) ? true : false;
    }

    //whitelist an already exisitinf ip
    public function monitorIp($ip)
    {
        //status 1 == whitelist
        $varValues = array(
            'status' => 0
        );
        $result = $this->db->addData('update', '#__osefirewall_ipmanagement', 'ip', $ip, $varValues);
        if($result !== 0)
        {
            $this->rmdir_recursive(OSE_WEBLOGFOLDER.ODS.$ip);
            return  $this->fwscanner->prepareSuccessMessage("The ip has been added to the whitelist");
        }
        else {
            return  $this->fwscanner->prepareErrorMessage("There was some problem in adding the ip to the whitelist");
        }
    }

    function rmdir_recursive($dir) {
        if(file_exists($dir))
        {
            foreach(scandir($dir) as $file) {
                if ('.' === $file || '..' === $file) continue;
                if (is_dir("$dir/$file")) $this->rmdir_recursive("$dir/$file");
                else unlink("$dir/$file");
            }
            rmdir($dir);
        }

    }


    //monitor an ip
    public function monitoranIP($ip)
    {
        //status 1 == whitelist
        $varValues = array(
            'status' => 0
        );
        $result = $this->db->addData('update', '#__osefirewall_ipmanagement', 'ip', $ip, $varValues);
        if($result !== 0)
        {
            return  $this->fwscanner->prepareSuccessMessage("The ip has been added to the monitor list");
        }
        else {
            return  $this->fwscanner->prepareErrorMessage("There was some problem in adding the ip to the monitor list");
        }
    }
    //add an ip to the database table
    public function addanIp($ip, $status,$duration = false)
    {
        $ip = oseFirewall::cleanupVar($ip);
        $isValid = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if($isValid) {
            if (!empty($duration) && $duration != 0) {
                $startDate = time();
                $timestamp =   date('Y-m-d H:i:s', strtotime("+$duration hour", $startDate));
                $this->saveTemporaryIPStatus($ip,$timestamp);
                if(file_exists(OSE_TEMP_IP_STATUS))
                {
                    return oseFirewallBase::prepareSuccessMessage("The ip has been added successfully");
                }else{
                    return oseFirewallBase::prepareErrorMessage("There was some problem in adding the Ip");
                }
            } else {
                //if the ip status is chnaged for always store the values in the db
            $ipexistsindb = $this->checkIfIPalreadyexistsInDB($ip);
            if (empty($ipexistsindb)) {
                $date = new DateTime();
                $current_timestamp = $date->getTimestamp();
                $varValues = array(
                    'ip' => $ip,
                    'status' => $status,
                    'ischecked' => 0,
                    'isspam' => 0,
                    'lastchecked' => 0,
                    'datetime' => date('Y-m-d h:i:s'),
                );
                $result = $this->db->addData('insert', '#__osefirewall_ipmanagement', '', '', $varValues);
            } else {
                //ip exists change status to blacklisted
                $varValues = array(
                    'status' => $status
                );
                $result = $this->db->addData('update', '#__osefirewall_ipmanagement', 'ip', $ip, $varValues);
            }
                if($status==1)
                {
                    $this->deleletIpFromTempFile($ip);
                }
            if ($result !== 0) {
                return $this->fwscanner->prepareSuccessMessage("The ip has been added successfully");
            } else {
                return $this->fwscanner->prepareErrorMessage("There was some problem in adding the ip");
            }
        }
        }
        else {
            return $this->fwscanner->prepareErrorMessage("Please enter an valid IP Address");
        }
    }

    //check if ip is white listed for a specific time
    public function checkIpIsWhiteListedLocalFile($ip)
    {
        $content = $this->getTempIpStatusContents();
        if(empty($content))
        {
            return false;
        }else{
            foreach($content as $iprecord)
            {
                if(isset($iprecord['ip']) && isset($iprecord['expireson']) && $iprecord['ip']==$ip) {
                    return ($this->isRecordIpValid($iprecord['expireson']));
                }
            }
            return false;
        }
    }
    //check if the ip is still valid
    public function isRecordIpValid($ip)
    {
        $curdate = new DateTime();
        $expireson = new DateTime($ip);
        if ($curdate > $expireson) {
            //expired
            return false;
        } else {
            //not expired
            return true;
        }
    }

    public function saveTemporaryIPStatus($ip,$timestamp)
    {
        if(file_exists(OSE_TEMP_IP_STATUS))
        {
            //get the old content
            $oldcontent = $this->getTempIpStatusContents();
            $newcontet = $this->prepareContent($ip,$timestamp);
            foreach($oldcontent as $key=>$value)
            {
                if($value['ip']==$ip)
                {
                   unset($oldcontent[$key]);

                }
            }
            array_push($oldcontent,$newcontet);
            //append the new one
            //write the content
            $this->writeTempIpStatusContents($oldcontent);
        }
        else {
            $content = $this->formatContent($ip,$timestamp);
            $this->writeTempIpStatusContents($content);
        }
    }

    public function deleletIpFromTempFile($ip)
    {
        if(file_exists(OSE_TEMP_IP_STATUS))
        {
            $oldcontent = $this->getTempIpStatusContents();
            foreach($oldcontent as $key=>$value)
            {
                if($value['ip']==$ip)
                {
                    unset($oldcontent[$key]);
                    $this->writeTempIpStatusContents($oldcontent);
                    return true;
                }
            }
            return false;
        }else{
            return false;
        }
    }

    public function writeTempIpStatusContents($content)
    {
        $filecontent = "<?php\n" . '$ipstatus = ' . var_export($content, true) . ";";
        $result = file_put_contents(OSE_TEMP_IP_STATUS, $filecontent);
        return ($result == false) ? false : true;
    }

    public function prepareContent($ip,$timestamp)
    {
        $temp = array(
            'ip' => $ip,
            'expireson' =>$timestamp,
        );
        return $temp;
    }
    public function formatContent($ip,$timestamp)
    {
        $temp = array(
            array(
                'ip' => $ip,
                'expireson' =>$timestamp,
            ),
        );
        return $temp;
    }

    public function getTempIpStatusContents()
    {
        $ipstatus = array();
        if (file_exists(OSE_TEMP_IP_STATUS)) {
            require(OSE_TEMP_IP_STATUS);
        }
        return $ipstatus;
    }


    //deletes all the entries from the databse
    public function clearIpTABLE()
    {
        $result = $this->db->truncateTable("#__osefirewall_ipmanagement");
        if($result !== 0)
        {
            $this->deleteEmailNotificationFile();
            return  $this->fwscanner->prepareSuccessMessage("The ip table has been cleared ");
        }
        else {
            return  $this->fwscanner->prepareErrorMessage("There was some problem in clearing the IP table");
        }
    }

    public function getIPInfo()
    {
        $columns = oRequest::getVar('columns', null);
        $limit = oRequest::getInt('length', 10);
        $start = oRequest::getInt('start', 0);
        $search = oRequest::getVar('search', null);
        $orderArr = oRequest::getVar('order', null);
        $sortby = null;
        $orderDir = 'asc';
        if (!empty($columns[1]['search']['value']))
        {
            $status = $columns[1]['search']['value'];
        } else
        {
            $status = null;
        }
        if (!empty($columns[2]['search']['value'])) {
            $type = $columns[2]['search']['value'];
        } else {
            $type = null;
        }
        if (isset($orderArr[0]['column']))
        {
            $sortby = $columns[$orderArr[0]['column']]['data'];
            $orderDir = $orderArr[0]['dir'];
        }
        $result = $this->getIPInfoList($search['value'], $status,$type, $start, $limit, $sortby, $orderDir);
        return $result;
    }

    //returns all the entries in the database table
    public function getIPInfoList($search, $status,$type, $start, $limit, $sortby, $orderDir)
    {
        $return = array ();
        if (!empty($search)) {$this->getWhereName ($search);}
        if (!empty($status)) {$this->getWhereStatus ($status);}
        $this->getOrderBy($sortby, $orderDir);
        if (!empty($type)) {
            $this->getWhereStatus($type);
        }
        $where = $this->db->implodeWhere($this->where);
        // Get Records Query;
        $temp_records = $this->getAllRecords($where);
        $return_temp = $this->filterIpsWithRecords($temp_records,true);
        if($sortby == "datetime")
        {
            foreach ($return_temp as $key => $part) {
                $sort[$key] = strtotime($part['datetime']);
            }
            if($orderDir == "asc")
            {
                $sort_order = SORT_ASC;
            }else{
                $sort_order = SORT_DESC;
            }
            array_multisort($sort, $sort_order, $return_temp);
        }
        if(!empty($limit))
        {
            $temp_final=  array_slice($return_temp, $start, $limit);
        }else{
            $temp_final = $return_temp;
        }
        $return['data'] = $temp_final;
        $return['recordsTotal'] = count($return['data']);
        $count = $this->getAllCountsNoVar($where);
        $return['recordsFiltered'] = $count['recordsFiltered'];
        return $return;
    }

    public function filterIpsWithRecords($records,$refine = false)
    {
        $return = array();
        if(empty($records))
        {
            return $return;
        }else{
            foreach ($records as $record) {
                if(isset($record['ip']) && !empty($record['ip']))
                {
                    $folderPath = OSE_WEBLOGFOLDER.ODS.$record['ip'];
                    if(file_exists($folderPath) && file_exists($folderPath."/blocked.php"))
                    {
                        if($refine)
                        {
                            unset($record['temp_status']);
                        }
                        $return[] = $record;
                    }else{
                        if($refine)
                        {
                            $temp_status = $record['temp_status'];
                        }else{
                            $temp_status = $record['status'];
                        }
                        if($temp_status==2 || $temp_status==1)
                        {
                            if($refine)
                            {
                                unset($record['status']);
                                $record['status'] =  $this->getStatusIcon($record['temp_status']);
                                unset($record['temp_status']);
                            }else{
                                unset($record['status']);
                                $record['status'] = $this->getStatusIcon($record['status']);
                            }
                            $return[] = $record;
                        }
                    }
                }
            }
            return $return;
        }
    }


    private function getAllCountsNoVar($where)
    {
        $return = array();
        // Get total count
        $query = "SELECT `ip`, `status` FROM `#__osefirewall_ipmanagement`";
        // Get filter count
        $this->db->setQuery($query . $where);
        $result = $this->db->loadResultList();
        $temp = $this->filterIpsWithRecords($result,false);
        $return['recordsFiltered'] = count($temp);
        return $return;
    }

    protected function getWhereName ($search) {
        $this->where[] = "`ip` LIKE ".$this->db->quoteValue($search.'%', true);
    }
    protected function getWhereStatus ($status) {
        if ($status == 2)
        {
            $this->where[] = "`status` = 2 ";
        }
        if ($status == 1)
        {
            $this->where[] = "`status` = 1 ";
        }
        if ($status == 3)
        {
            $this->where[] = "`status` = 0 ";
        }

    }
    protected function getOrderBy ($sortby, $orderDir) {
        if (empty($sortby))
        {
            $this->orderBy= " ORDER BY `dateadded` DESC";
        }
        else
        {
            if($sortby == 'datetime')
            {
                $sortby = 'dateadded';
            }
            $this->orderBy= " ORDER BY ".$this->db->quoteKey($sortby).' '.addslashes($orderDir);
        }
    }
    protected function getLimitStm ($start, $limit) {
        if (!empty($limit))
        {
            $this->limitStm = " LIMIT ".(int)$start.", ".(int)$limit;
        }
    }

    public function getAllRecords($where)
    {
        $sql = "SELECT * FROM `#__osefirewall_ipmanagement`";
        $query = $sql.$where.$this->orderBy;
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        $result = $this->formatIPLog($temp);
        return  $result['data'];
    }

    public function getIPinfoDb()
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE 1";
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        return $temp;
    }

    public function formatIPLog($array)
    {
        $temp = array();
        $i= 0;
        foreach($array as $record)
        {
            $temp[$i]['id'] = $record['id'];
            $temp[$i]['ip'] = $record['ip'];
            $temp[$i]['status'] = ($record['status'] == 2 || $record['status'] == 0) ? $this->getStatusIcon($record['status']).' '.'<i class="text-success glyphicon glyphicon-info-sign" style="cursor:pointer; font-size:20px; float:right; color:#1cab94;" href="javascript:void(0);" onclick="viewAttackInfo(\'' . $record['ip'] . '\')" title = "Find out the reason why this IP has been blocked"></i>': $this->getStatusIcon($record['status']);
            $temp[$i]['temp_status'] = $record['status'];
            $temp[$i]['datetime'] = $record['dateadded'];
            $i++;
        }
        $result['data'] =$temp;
//        $result['recordsFiltered'] = count($temp);
//        $result['recordsTotal'] =count($temp);
        return $result;
    }

    public function viewAttackInfo($ip)
    {
        oseFirewall::loadLibClass('fwscannerv7','fwstatsv7');
        $fs = new fwstatsv7();
        $result = $fs->preapreAttackInfoContent($ip);
        return $result;
    }

    //aceepts list of ips that needs to be deleted
    public function deleteIps($array)
    {
        $ipArray = $this->getIPfromIds($array);
        foreach($array as $record)
        {
            if(!empty($record))
            {
//                $ip = $temp->ip;
                $query = "DELETE FROM `#__osefirewall_ipmanagement` WHERE `id`=".$this->db->quoteValue($record);
                $this->db->setQuery($query);
                $this->db->loadObject();
            }else {
                return $this->fwscanner->prepareErrorMessage("There was some problem in deleting the chose ip(s)");
            }
        }
        $this->updateEmailNotificationFile($array,$ipArray);
        return $this->fwscanner->prepareSuccessMessage("The chosen IP's have been deleted");
    }

    //get the $_FILES variable of the uploadedd file
    public function importCSV($files)
    {
        //if the file is not uploaded
        if (empty($files))
        {
            return $this->fwscanner->prepareErrorMessage("Please upload a CSV file, there is no files uploaded");
        }
        else
        {
            $file = $files['csvfile'];
            //check if only the cvs file is uploaded
            if (!in_array($file['type'], array('application/csv', 'text/csv', 'text/comma-separated-values', 'application/vnd.ms-excel')))
            {
                //wrong file format
                return $this->fwscanner->prepareErrorMessage("Please upload CSV files, file types apart from the CSV is not accepted.");
            }
            else
            {
                //csv file
                $result = $this->insertCSVFileinDb($file);
                if ($result['status'] == 1)
                {
                    return $this->fwscanner->prepareSuccessMessage("There CSV files was imported successfully");
                }
                else
                {
                    return $this->fwscanner->prepareErrorMessage("There was some problem in improting the CVS file");
                }
            }
        }
    }

    //get the data row by row and add it to the database
    public function insertCSVFileinDb($file)
    {
        $row = 1;
        $result = true;
        if (($handle = fopen($file['tmp_name'], "r")) !== FALSE) {
            while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
                //get row by row data
                if ($row == 1)
                {
                    //if the heading name of the fields  are not same asa the database one
                    if ($data != $this->headerArray())
                    {
                        return $this->fwscanner->prepareErrorMessage("The CSV file heading format is incorrect. Please follow the instruction to create the CSV file.");
                    }
                }
                else
                {
                    //add row by row to the database table
                    $result = $this->addCSVIPs($data[1], $data[2], $data[3],$data[4],$data[5],$data[6]);
                    if($result['status'] == 0)
                    {
                        return $result;
                    }
                }
                $row++;
            }
            fclose($handle);
        }
        return $result;
    }

    public function addCSVIPs($ip,$status,$ischecked,$isspam,$lastchecked,$dateadded)
    {

        //check if any one of the value is empty
        if((isset($ip)||isset($status)||isset($ischecked)||isset($isspam)||isset($lastchecked)||isset($dateadded))) {
            //check if the ip alredy exists in the databse
            $ipexistsindb = $this->checkIfIPalreadyexistsInDB($ip);
            if (empty($ipexistsindb))
            {
                $varValues = array(
                    'ip' => $ip,
                    'status' => $status,
                    'ischecked' =>$ischecked,
                    'isspam' => $isspam,
                    'lastchecked' =>$lastchecked,
//                    'dateadded' => $dateadded,
                    'dateadded' => date('Y-m-d h:i:s'),
                );
                $result = $this->db->addData('insert', '#__osefirewall_ipmanagement', '', '', $varValues);
                //the result will be 0 if the insert was not successfull
                if ($result !== 0)
                {
                    //insert was successfull
                    return $this->fwscanner->prepareSuccessMessage("The record for the ip " . $ip . "has been successfully imported");
                } else
                {
                    return $this->fwscanner->prepareErrorMessage("There was some problem in importing the record for " . $ip);
                }
            } else
            {
                //the ip already exists in the database
                return $this->fwscanner->prepareSuccessMessage("The record for the ip already exists in the database");
            }
        }
        else
        {
            //one of the values is empty
            return $this->fwscanner->prepareErrorMessage("The values that needs to be entered in the database are empty");
        }
    }

    //contains all the list of heading field of the ipamanagement table
    protected function headerArray () {
        return array("id", "ip", "status", "ischecked", "isspam", "lastchecked", "dateadded");
    }

    // gets the comnplete path for the csv file that needs to be saved
    public function getCompleteCSVFilepath($filename)
    {
     $filepath = OSE_CSV_EXPORTFILES.ODS.$filename.".txt";
     return $filepath;
    }

    //sends the header with the csv file content
    public function downloadcvs_fws7($filename)
    {
        $fileContent = $this->getDownloadCSVContent();
            if (ob_get_contents()) {
                ob_clean();
            }
        header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
        header("Content-Length: " . strlen($fileContent));
        // Output to browser with appropriate mime type, you choose ;)
        header("Content-type: text/csv");
        header("Content-Disposition: attachment; filename=$filename");
        print_r($fileContent);
        exit;
    }

    /*
     * Download csv new updated code
     */

    public function getDownloadCSVContent()
    {
        $output = implode(",", $this->headerArray()) . "\n";
        $results = $this->getIPinfoDb();
        foreach ($results as $data) {
            $output .= $this->getTmpOutput($data) . "\n";
        }
        return $output;
    }

    private function getTmpOutput($data)
    {
        $tmp = array();
        $tmp[] = $data['id'];
        $tmp[] = $data['ip'];
        $tmp[] = $data['status'];
        $tmp[] = $data['ischecked'];
        $tmp[] = $data['isspam'];
        $tmp[] = $data['lastchecked'];
        $tmp[] = $data['dateadded'];
        $return = implode(",", $tmp);
        return $return;
    }

    //attach the link to the export button
    public function getExportButton()
    {
        oseFirewall::loadFiles();
        $time = date("Y-m-d");
        $filename = "ip-export-" . $time . ".csv";
        $centnounce = isset($_SESSION['centnounce']) ? $_SESSION['centnounce'] : oseFirewall::loadNounce();
        $url = EXPORT_DOWNLOAD_URL_FWS7 . urlencode($filename) . "&centnounce=" . urlencode($centnounce);
        $exportButton = '<a href="' . $url . '"  id="export-ip-button" target="_blank" class="btn-new tl-center"><i class="glyphicon glyphicon-export"></i> ' . oLang::_get("GENERATE_CSV_NOW") . '</a>';
        return $exportButton;
    }


    public function getStatusIcon($status)
    {
        switch ($status)
        {
            case '1':
                return "<a href='javascript:void(0);' title = 'WhiteList' onClick= '#'><i class='text-success glyphicon glyphicon-ok-sign' title = 'This IP is scurrently whitelisted'></i></a>";
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

    //check  if the ip has been checked for spam
    public function isspamcheck($ip)
    {
//        $this->ip = '5.248.164.72';
        $query = "SELECT `ischecked`, `isspam`,`lastchecked` FROM ".$this->db->quoteKey($this->iptable)." WHERE `ip` = " . $this->db->quoteValue($ip);
        $this->db->setQuery($query);
        $result = (object)($this->db->loadResult());
        $temp = array();
        if(!empty($result->ischecked))
        {
            $temp['status'] = 1;
            $temp['ischecked'] = $result->ischecked;
            $temp['isspam'] = $result->isspam;
            $temp['timestamp'] = $result->lastchecked;
            return $temp;

        }else {
            //set the values if the record does not exists
            $temp['status'] =0;
            $temp['ischecked'] =0;
            $temp['isspam'] = 0;
            $temp['timestamp'] =0;
            return $temp;
        }
    }

    //update the spam check values in the databse
    public function updateSpamCheck($ip,$type,$value,$current_timestamp)
    {
        $varValues = array(
            'ischecked' => (int)$type,
            'isspam' => (int)$value,
            'lastchecked' => $current_timestamp
        );
        $this->db->addData('update', $this->iptable, 'ip', $ip, $varValues);
    }

    //add an entry into the databsae for the spam check
    public function insertSpamCheck($ip,$status,$type,$value,$current_timestamp)
    {
        $varValues = array(
            'ip' => $ip,
            'status' =>(int)$status,
            'ischecked' => (int)$type,
            'isspam' =>(int)$value,
            'lastchecked' => $current_timestamp,
            'dateadded'=> date('Y-m-d h:i:s'),
        );
        $this->db->addData('insert', $this->iptable, '', '', $varValues);
    }

    //deletes all the blacklisted and monitored records from the db if they are older than 30 days
    public function cronJobsIPTable()
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `status`= 1 OR `status` = 2";
        $this->db->setQuery($query);
        $result = $this->db->loadArrayList();
        if(!empty($result))
        {
            foreach($result as $record)
            {
                $isexpired = $this->checkRecordExpiry($record['dateadded']);
                if($isexpired)
                {
                    $temp = $this->deleteIps(array($record['id']));
                    if($temp['status'] == 0)
                    {
                        return $temp;
                    }
                }
            }
            return  $this->fwscanner->prepareSuccessMessage("The blocklisted and monitored ips have been deleted");
        }else {
            return $this->fwscanner->prepareErrorMessage("There are no records for the blacklisted and monitored ips");
        }
    }

    //CRON JOB => to chheck the date of the record and returns true if the diffrene is more than 30 days
    //TODO
    public function checkRecordExpiry($record)
    {
        if(isset($record))
        {
            $ts1 = strtotime($record);
            $ts2 =  strtotime(date('Y-m-d h:i:s'));
            $seconds_diff = $ts2 - $ts1;
            $days = $seconds_diff/86400;
            if((int)$days >30)
            {
                //the record has expired
                return true;
            }else {
                //the records has not expired
                return false;
            }
        }else {
            return true;
        }
    }

    public function importipsfromv6()
    {
        $return = array();
        $valuesToInsert = array();
        $oseFirewallStat = new oseFirewallStat();
        if (oseFirewall::isDBReady())
        {
            $return = $oseFirewallStat->getACLIPMap();
        }
        if(!empty($return))
        {
            if(isset($return['data']) && !empty($return['data']))
            {
                foreach($return['data'] as $value)
                {
                    if(property_exists($value,'ip32_start'))
                    {
                        $temp = $this->checkIfIPalreadyexistsInDB($value->ip32_start);
                        if(empty($temp))
                        {
                            if($value->statusraw == 3)
                            {
                                $finalStatus = 1;
                            }elseif($value->statusraw == 2)
                            {
                                $finalStatus = 0;
                            }else if($value->statusraw == 1)
                            {
                                $finalStatus = 2;
                            }else{
                                $finalStatus = 0;
                            }
                           $valuesToInsert = array(
                            'ip'=>$value->ip32_start,
                               'status'=> $finalStatus,
                               'dateadded'=>$value->datetime,
                               'ischecked' =>0,
                               'isspam' => 0,
                           ) ;
                            $result = $this->db->addData('insert', '#__osefirewall_ipmanagement', '', '', $valuesToInsert);
                            unset($valuesToInsert);
                            if ($result == 0) {
                                return oseFirewallBase::prepareErrorMessage("There was some problem in adding the ip");
                            }
                        }
                    }
                }
            }
        }else{
            return oseFirewallBase::prepareSuccessMessage("There are no Ips available in version 6.6. to sync");
        }
        return oseFirewallBase::prepareSuccessMessage("All the Ips from the version 6.6 has been synced to version 7 successfully");
    }

    public function getTempWhiteListedIpsList()
    {
        $content = $this->getTempIpStatusContents();
        if(!empty($content))
        {
            $finalcontent="Follwing is the list of whiteListed IP's <br/><table border='1' cellpadding='10' cellspacing='10'>";
            $finalcontent.="<tr><th>Ip(s)</th><th>Expires In</th></tr>";
            foreach($content as $key=>$value)
            {
                $datetime1 = new DateTime();
                $datetime2 = new DateTime($value['expireson']);
                $interval = $datetime1->diff($datetime2);
                $hours = (int)$interval->format("%r%h");
                $mins = (int)$interval->format("%r%i");
                $finalcontent.="<tr><td>".$value['ip']."</td><td>"."$hours Hours $mins Mins".'  <i class="glyphicon glyphicon-minus-sign" href="javascript:void(0);" onclick="deleteTempWhiteListIps(\'' . $value['ip'] . '\')" title = "Delete the ip fro white listed ips list"></i></td></tr>';
            }
            $finalcontent.="</table>";
            return oseFirewallBase::prepareSuccessMessage($finalcontent);

        }else{
         return oseFirewallBase::prepareErrorMessage("There are no Ip's that are temporarily whitelisted");
        }
    }

    public function deleteTempWhiteListIps($ip)
    {
        $result = $this->deleletIpFromTempFile($ip);
        if($result)
        {
            return oseFirewallBase::prepareSuccessMessage("$ip has been removed from temporary whitelisted list");
        }else{
            return oseFirewallBase::prepareErrorMessage("There was some problem in removing theip : $ip from whitelisted list");
        }

    }

    public function clearOldIpsData()
    {
        //keep whitelisted and the ips blocked by the user
        //deleete the old temp records
        $this->removeExpiredTempIps();
    }

    public function removeExpiredTempIps()
    {
        if(file_exists(OSE_TEMP_IP_STATUS))
        {
            $content = $this->getTempIpStatusContents();
            foreach($content as $key=>$iprecord)
            {
                if(isset($iprecord['ip']) && isset($iprecord['expireson'])) {
                    if(!$this->isRecordIpValid($iprecord['expireson']))
                    {
                        unset($content[$key]);
                    }
                }
            }
            $this->writeTempIpStatusContents($content);
            return oseFirewallBase::prepareSuccessMessage("Expired records have been deleted");
        }else{
            return oseFirewallBase::prepareSuccessMessage("No temp ips exist");
        }
    }

    public function getMonitorandBlackListIps()
    {
        $query = "SELECT * FROM `#__osefirewall_ipmanagement` WHERE `status`= 2 OR `status`= 0";
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }
    //removes the whitelisted ips
    public function removeExpiredIps()
    {
        $deleteIpsList = array();
        $ipsList = $this->getMonitorandBlackListIps();
        if(!empty($ipsList))
        {
            foreach($ipsList as $key=>$record)
            {
             if(isset($record['status']) && $record['status']==2)
             {
                 //black listed ips
                 //delete if the ip has been bloced manually
                 oseFirewallBase::callLibClass('fwscannerv7','fwstatsv7');
                 $this->fwscannerv7stats = new fwstatsv7();
                 $attackInfo_temp = $this->fwscannerv7stats->getAttackFileContent($record['ip']);
                 if(!empty($attackInfo_temp) && $this->lastAddedCheck($record['dateadded']))
                 {
                    //no attack log exists -->manually blocked by the user //delete
                    array_push($deleteIpsList,$record['ip']);
                 }
             }elseif(isset($record['status']) && $record['status']==0){
                 //monitor check if the last check >30 days then delete the ips
                 if(isset($record['dateadded']) && $this->lastAddedCheck($record['dateadded']))
                 {
                     array_push($deleteIpsList,$record['ip']);
                 }
             }
            }
            if(!empty($deleteIpsList))
            {
                $this->deleteIpsArray($deleteIpsList);
                return oseFirewallBase::prepareSuccessMessage("All the expired IPs has been deleted");
            }
        }else{
            return oseFirewallBase::prepareSuccessMessage("There are no blacklisted and monitored ips ");
        }
    }


    //if last addded for ip greater than 30 days return true
    public function lastAddedCheck($date)
    {
        $datetime1 = new DateTime();
        $datetime2 = new DateTime($date);
        $interval = $datetime1->diff($datetime2);
        $year =  $interval->format('%y');
        $month =  $interval->format('%m');
        $days =  $interval->format('%a');
        if($year>=1 || $month>=1 || $days>=30)
        {
            return true;
        }else{
            return false;
        }
    }

    public function deleteIpsArray($array)
    {
        if(!empty($array))
        {
            $query = "DELETE FROM `#__osefirewall_ipmanagement` WHERE `ip` IN ('".implode("','",$array)."')";
            $this->db->setQuery($query);
            $this->db->loadObject();
        }
    }


    public function updateEmailNotificationFile($idArray,$ipArray = false)
    {
        $formattedIpArray = array();
        if($ipArray == false)
        {
            $ipArray = $this->getIPfromIds($idArray);
        }
        if(empty($ipArray))
        {
            return true;
        }else{
            foreach($ipArray as $record)
            {
                if(isset($record['ip']))
                {
                    $formattedIpArray[] = $record['ip'];
                }
            }
           if(!empty($formattedIpArray))
           {
               oseFirewallBase::callLibClass('fwscannerv7','emailNotificationMgmt');
               $emailMgmt = new emailNotificationMgmt(false);
               $emailMgmt->removeIpsFromEmailNotification($formattedIpArray);
           }
        }
    }

    public function getIPfromIds($idArray)
    {
        $query = "SELECT `ip` FROM `#__osefirewall_ipmanagement` WHERE `id` IN ('".implode("','",$idArray)."')";;
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        return $temp;
    }


    public function deleteEmailNotificationFile()
    {
        oseFirewallBase::callLibClass('fwscannerv7','emailNotificationMgmt');
        $emailMgmt = new emailNotificationMgmt(false);
        $emailMgmt->deleteNotificationFile();
    }


    public function getAllIpRecordsFromDb()
    {
        $query = "SELECT `ip` FROM `#__osefirewall_ipmanagement` WHERE 1";
        $this->db->setQuery($query);
        $ips = $this->db->loadResultList();
        return $ips;
    }



}