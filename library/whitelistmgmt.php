<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 11/07/2016
 * Time: 8:32 AM
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
class whitelistmgmt{
    private $whitelistmgmt_table = '#__osefirewall_whitelistmgmt';
    private  $orderBy = null;
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

        $whitelistmgmt_tableexists = $this->db->isTableExists($this->whitelistmgmt_table);
        if (!$whitelistmgmt_tableexists) {
            //if the ip table does not exist
            oseFirewallBase::createWhitelistMgmtTable($this->db);
        }
        oseFirewall::callLibClass('fwscannerv7','fwscannerv7');
        $this->fwscanner = new oseFirewallScannerV7();
    }


    //returns the list of all the variables and the strings from the databse
    public function getEntityList()
    {

        $columns = oRequest::getVar('columns', null);
        $limit = oRequest::getInt('length', 15);
        $start = oRequest::getInt('start', 0);
        $search = oRequest::getVar('search', null);
        $orderArr = oRequest::getVar('order', null);
        $sortby = null;
        $orderDir = 'asc';
        $status = $columns[4]['search']['value'];
        if (!empty($orderArr[0]['column']))
        {
            $sortby = $columns[$orderArr[0]['column']]['data'];
            $orderDir = $orderArr[0]['dir'];
        }
        if (!empty($columns[2]['search']['value'])) {
            $type = $columns[2]['search']['value'];
        } else {
            $type = null;
        }
        $result = $this->getListDB($search['value'],$status,$type, $start, $limit, $sortby, $orderDir);
        return $result;

    }

    private function getListDB($search,$status,$type, $start, $limit, $sortby, $orderDir)
    {
        $return = array();
        if (!empty($search)) {
            $this->getWhereNameLog($search);
        }
        if (!empty($status)) {
            $this->getWhereStatus($status);
        }
        if (!empty($type)) {
            $this->getWhereType($type);
        }
        $this->getOrderByLog($sortby, $orderDir);
        if (!empty($limit)) {
            $this->getLimitStm($start, $limit);
        }
        $where = $this->db->implodeWhere($this->where);
        $return= $this->getAllLogRecords($where);
        return $return;
    }
    protected function getLimitStm($start, $limit)
    {
        if (!empty($limit)) {
            $this->limitStm = " LIMIT " . (int)$start . ", " . (int)$limit;
        }
    }
    protected function getWhereType($type)
    {
        if($type == 1)
        {
            $this->where[] = "`entity_type` = 'VARIABLE'";
        }
        if($type ==2)
        {
            $this->where[] = "`entity_type` = 'STRING'";
        }
    }

    protected function getWhereStatus($status)
    {
        if($status == 3)
        {
            $this->where[] = "`status` = " . 0;
        }else if ($status == 1) {
            $this->where[] = "`status` = " . 1;
        }
        else if ($status == 2) {
            $this->where[] = "`status` = " . 2;
        }
    }
    private function getWhereNameLog($search)
    {
        $this->where[] = "`entity` LIKE " . $this->db->quoteValue($search . '%', true);
    }

    private function getOrderByLog($sortby, $orderDir)
    {
        if (empty($sortby)) {
            $this->orderBy = " ORDER BY `id` ASC";
        } else {
            $this->orderBy = " ORDER BY " . $this->db->quoteKey($sortby) . ' ' . addslashes($orderDir);
        }
    }

    private function getAllLogRecords($where)
    {
        $sql = "SELECT * FROM ".$this->db->quoteKey($this->whitelistmgmt_table);
        $query = $sql . $where . $this->orderBy . " " . $this->limitStm;
        $this->db->setQuery($query);
        $temp = $this->db->loadResultList();
        $result = $this->formatEntityList($temp);
        $count = $this->getAllCounts($where);
        $result['recordsTotal'] = $count['recordsTotal'];
        $result['recordsFiltered'] = $count['recordsFiltered'];
        return $result;
    }

    private function getAllCounts($where)
    {
        $return = array();
        // Get total count
        $sql = 'SELECT COUNT(`id`) AS count FROM '.$this->db->quoteKey($this->whitelistmgmt_table);
        $this->db->setQuery($sql);
        $result = $this->db->loadObject();
        $return['recordsTotal'] = $result->count;
        // Get filter count
        $this->db->setQuery($sql . $where);
        $result = $this->db->loadObject();
        $return['recordsFiltered'] = $result->count;
        return $return;
    }


    public function formatEntityList($array)
    {
        $temp = array();
        $i= 0;
        foreach($array as $record)
        {
            $temp[$i]['id'] = $record['id'];
            $temp[$i]['entity'] = $record['entity'];
            $temp[$i]['entity_type'] = $record['entity_type'];
            $temp[$i]['request_type'] = $record['request_type'];
            $temp[$i]['status'] = $this->getStatusIcon($record['status']);
            $i++;
        }
        $result['data'] = $temp;
        return $result;
    }

    /*
     * change the status of an record based on the id provided
     *  0=>ignore/whitelist
     *  1=> filter
     *  2=> scan
     */
    public function changeStatusOfEntities($array, $status)
    {
        if(!empty($array))
        {
            foreach($array as $record)
            {
                $varValues = array(
                    'status' => $status,
                );
                $result = $this->db->addData('update', $this->whitelistmgmt_table, 'id', (int)$record, $varValues);
                if ($result == 0) {
                    return $this->prepareErrorMessage("There was some problem in updating the id" . $record ." to the status ".$this->getStatusName($status));
                }
            }
            $this->updateLocalFiles();
            return $this->prepareSuccessMessage("The selected ids have been added to the ".$this->getStatusName($status)." list");
        }else {
            return $this->prepareErrorMessage("There id array is empty");
        }
    }


    //returns the name of the list based on the status value
    public function getStatusName($status)
    {
        if($status == 0)
        {
            return 'Whitelist';
        }else if($status == 1)
        {
            return 'Filter';
        }elseif($status == 2)
        {
            return 'Scan';
        }
    }

    //deletes the user selected records based on the matching ids from the database
    public function deleteRecords($array)
    {
        foreach($array as $record)
        {
            if(!empty($record))
            {
//                $ip = $temp->ip;
                $query = "DELETE FROM ".$this->db->quoteKey($this->whitelistmgmt_table). " WHERE `id`=".$this->db->quoteValue($record);
                $this->db->setQuery($query);
                $this->db->loadObject();
            }else {
                return $this->prepareErrorMessage("There was some problem in deleting the chose record(s)");
            }
        }
        $this->updateLocalFiles();
        return $this->prepareSuccessMessage("The chosen records have been deleted");
    }

    //deletes the complete record table
    public function clearRecords()
    {
        $result = $this->db->truncateTable($this->whitelistmgmt_table);
        if($result !== 0)
        {
            $this->updateLocalFiles();
            return  $this->prepareSuccessMessage("All the records have been deleted successfully");
        }
        else {
            return  $this->prepareErrorMessage("There was some problem in deleting all the records of the white list management table ");
        }
    }

    public function addEntity($entity_name,$entity_type,$request_type,$status)
    {
        $entity_name_existsinDb = $this->checkIfEntityalreadyexistsInDB($entity_name);
            if (empty($entity_name_existsinDb)) {
                $varValues = array(
                    'entity' => oseFirewallBase::cleanupVar($entity_name),//cleanupVar
                    'entity_type' => $entity_type,
                    'request_type' => $request_type,
                    'status' => $status,
                );
                $result = $this->db->addData('insert', $this->whitelistmgmt_table, '', '', $varValues);
            } else {
                //entity already exists change status to blacklisted
                $varValues = array(
                    'entity_type' => $entity_type,
                    'request_type' => $request_type,
                    'status' => $status,
                );
                $result = $this->db->addData('update', $this->whitelistmgmt_table, 'entity', oseFirewallBase::cleanupVar($entity_name), $varValues);
            }
            if ($result !== 0) {
                if($status == 0)
                {
                    $this->updateLocalFiles();
                }
                return $this->prepareSuccessMessage("The ".strtolower($entity_type)." has been added successfully");
            } else {
                return $this->prepareErrorMessage("There was some problem in adding the ".strtolower($entity_type));
            }
    }

    public function checkIfEntityalreadyexistsInDB($entityname)
    {
        $query = "SELECT * FROM ".$this->db->quoteKey($this->whitelistmgmt_table)." WHERE `entity`=" . $this->db->quoteValue($entityname);
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        return $result;
    }

    //STANDARAD ERROE MESSAGE
    public function prepareErrorMessage($message)
    {
        $result['status'] = 'ERROR';
        $result['result'] = $message;
        return $result;
    }

    //STANDARD SUCCESS MESSAGE
    public function prepareSuccessMessage($message)
    {
        $result['status'] = 'SUCCESS';
        $result['result'] = $message;
        return $result;
    }

    public function loadDefaultVariables($type)
    {
        $variablesList = $this->getDefaultVariables($type);
        foreach($variablesList as $record) {
            $entity_name_existsinDb = $this->checkIfEntityalreadyexistsInDB($record['entity_name']);
            if (empty($entity_name_existsinDb)) {
                $varValues = array(
                    'entity' => $record['entity_name'],
                    'entity_type' => "VARIABLE",
                    'request_type' => $record['request_type'],
                    'status' => 0,
                );
                $result = $this->db->addData('insert', $this->whitelistmgmt_table, '', '', $varValues);
            } else {
                //entity already exists change status to blacklisted
                $varValues = array(
                    'entity_type' => "VARIABLE",
                    'request_type' => $record['request_type'],
                    'status' => 0,
                );
                $result = $this->db->addData('update', $this->whitelistmgmt_table, 'entity', $record['entity_name'], $varValues);
            }
            if ($result == 0)  {
                return $this->prepareErrorMessage("There was some problem in adding the ".$record['entity_name']);
            }
        }
        $this->updateLocalFiles();
        return $this->prepareSuccessMessage("The white list variables has been added successfully");
    }


    public function getDefaultVariables($type)
    {
        if(!isset($type))
        {
            if(OSE_CMS == 'wordpress')
            {
                $type = 'WORDPRESS';
            }else {
                $type = 'JOOMLA';
            }
        }
        $result = array();
        $array = array();
        $oseFirewallStat = new oseFirewallStat();
        if($type == 'WORDPRESS')
        {
            $array = $oseFirewallStat->getWordpressKeys();
        }
        else if($type == 'JOOMLA')
        {
            $array = $oseFirewallStat->getJoomlaKeys();
        }
        else if($type == 'JOOMLASOCIAL')
        {
            $array = $oseFirewallStat->getJoomlaSocialKeys();
        }
        $result = $this->formatDefaultVariables($array);
        return $result;
    }

    public function formatDefaultVariables($array)
    {
        $result = array();
        foreach($array as $record)
        {
            $temp = explode('.',$record);
            $temp1['request_type'] = $temp[0];
            $temp1['entity_name'] = $temp[1];
            array_push($result,$temp1);
        }


        return $result;
    }

    public function getDefaultUnformattedList($type)
    {
        $oseFirewallStat = new oseFirewallStat();
        $array = array();
        if($type == 'WORDPRESS')
        {
            $array = $oseFirewallStat->getWordpressKeys();
        }
        else if($type == 'JOOMLA')
        {
            $array = $oseFirewallStat->getJoomlaKeys();
        }
        else if($type == 'JOOMLASOCIAL')
        {
            $array = $oseFirewallStat->getJoomlaSocialKeys();
        }
        return $array;
    }

    public function importVariables()
    {
        //check if the entires exist
        //get the list from the db
        //try to insert if does not exist
        // skip if the entry already exists
        $variableList = $this->getExistingVariables();
        $result = $this->formatExistingVariables($variableList['result']);
        foreach($result as $record) {
            $entity_name_existsinDb = $this->checkIfEntityalreadyexistsInDB($record['entity_name']);
            if (empty($entity_name_existsinDb)) {
                $varValues = array(
                    'entity' => $record['entity_name'],
                    'entity_type' => "VARIABLE",
                    'request_type' => $record['request_type'],
                    'status' => $record['status'],
                );
                $result = $this->db->addData('insert', $this->whitelistmgmt_table, '', '', $varValues);
            }
            if ($result == 0)  {
                return $this->prepareErrorMessage("There was some problem in adding the ".$record['entity_name']);
            }
        }
        $this->updateLocalFiles();
        return $this->prepareSuccessMessage("The variables have been imported successfully");
    }

    //get the list of variables from the old firewall scanner configuration
    public function getExistingVariables()
    {
        $vartable = '#__osefirewall_vars';
        $table_exists = $this->db->isTableExists($vartable);
        if($table_exists)
        {
            $query = "SELECT `keyname` ,`status` FROM ".$this->db->quoteKey($vartable)." WHERE 1";
            $this->db->setQuery($query);
            $temp = $this->db->loadResultList();
            if(empty($temp))
            {
                return $this->prepareErrorMessage("The Vars Table is empty");
            }else {
                return $this->prepareSuccessMessage($temp);
            }
        }else {
            return $this->prepareErrorMessage("Tne Vars Table does not exists");
        }
    }
    //get the request type and the variable name from the database
    public function formatExistingVariables($array)
    {
        $result= array();
        foreach($array as $record)
        {
            $temp = explode('.',$record['keyname']);
            $temp1['request_type'] = $temp[0];
            $temp1['entity_name'] = $temp[1];
            if(isset($record['status']))
            {
                if($record['status']==1) {$temp1['status'] = 2;}
                if($record['status']==2) {$temp1['status'] = 1;}
                if($record['status']==3) {$temp1['status'] = 0;}
            }else{
                $temp1['status'] = 1;
            }
            array_push($result,$temp1);
        }
        return $result;
    }


    public function getStatusIcon($status)
    {
//        return "<a href='javascript:void(0);' title = 'WhiteList' onClick= 'changeItemStatus(" . urlencode($id) . ", 2)' ><i class='text-success glyphicon glyphicon-ok-sign'></i></a>";
        switch ($status)
        {
            case '0':
                return "<a href='javascript:void(0);' title = 'WhiteList' onClick= '#'><i class='text-success glyphicon glyphicon-ok-sign' title = 'This variable has been whitelisted'></i></a>";
                break;
            case '1':
                return "<a href='javascript:void(0);' title = 'Filter' onClick= '#' ><i class='text-yellow glyphicon glyphicon-eye-open' title = 'This variable is actively filtred'></i></a>";
                break;
            case '2':
                return "<a href='javascript:void(0);' title = 'Scan' onClick= '#' ><i class='text-block glyphicon glyphicon-minus-sign' title = 'This variable is actively scanned'></i></a>";
                break;
            default:
                return '';
                break;
        }
    }

    /*
     * code to manage the local files that stores the white listed string and the variables
     *
     */

    //get the contents of the variable list file
    public function getWhiteListVariablesFile()
    {
        $variable = array();
        if(file_exists(OSE_WHITELIST_VARIABLESFILE))
        {
            require (OSE_WHITELIST_VARIABLESFILE);
        }
        return $variable;
    }
    //get the content of the string list file
    public function getWhiteListStringsFile()
    {
        $string = array();
        if(file_exists(OSE_WHITELIST_STRINGFILE))
        {
            require (OSE_WHITELIST_STRINGFILE);
        }
        return $string;
    }

    //get the records which are whitelisted
    public function getWhiteListEntitiesfromDB()
    {
        $query = "SELECT * FROM ".$this->db->quoteKey($this->whitelistmgmt_table)." WHERE `status`= 0";  // get the list of white list variables
        $this->db->setQuery($query);
        $result = $this->db->loadResultList();
        if(!empty($result))
        {

        }else {
            return $this->prepareErrorMessage("There are no whitelisted variables or string ");
        }
        return $result;
    }

    //generate local file containing whitelist variables
    public function generateWhiteListVariablesFiles($content)
    {
        $contenttoput = "<?php\n" . '$variable = ' . var_export($content, true) . ";";
        $result = file_put_contents(OSE_WHITELIST_VARIABLESFILE, $contenttoput);
        return $result;
    }

    //write the whitelisted strings list into the local file
    public function generateWhiteListStringFile($content)
    {
        $contenttoput = "<?php\n" . '$string = ' . var_export($content, true) . ";";
        $result = file_put_contents(OSE_WHITELIST_STRINGFILE, $contenttoput);
        return $result;
    }

    //complete mechanism that updates the local file of the file
    public function updateLocalFiles()
    {
        //update the variable and the string file
        //get the list of whitelisted vriables and the strings
        $list = $this->prepareEntityList();
        //write them into the local files
        $result_var = $this->generateWhiteListVariablesFiles($list['variable']);
        $result_str = $this->generateWhiteListStringFile($list['string']);
    }

    //format and seperates into variables and strings
    public function prepareEntityList()
    {
        $variableList = array();
        $stringList = array();
        $list = $this->getWhiteListEntitiesfromDB();
        $stringIndex = 0;
        $variableIndex = 0;
        foreach($list as $key=>$value)
        {
            if($value['entity_type'] == 'VARIABLE')
            {
                $variableList[$variableIndex]['id'] = $value['id'];
                $variableList[$variableIndex]['variable'] = $value['request_type'].".".$value['entity'];
                $variableIndex ++;
            }
            if($value['entity_type'] == 'STRING')
            {
                $stringList[$stringIndex]['id'] = $value['id'];
                $stringList[$stringIndex]['string'] = $value['entity'];
                $stringIndex ++;
            }
        }
        $result['variable'] = $variableList;
        $result['string'] = $stringList;
        return $result;
    }

    //returns the content of the files
    public function getContentOfFiles($type)
    {
        if($type == "VARIABLE")
        {
         return $this->getWhiteListVariablesFile();
        }
        else if($type == "STRING")
        {
         return $result = $this->getWhiteListStringsFile();
        }
    }


    public function addWhiteListEntity($entity)
    {
        $temp = explode('.',$entity);
        if(isset($temp[0])&& isset($temp[1]))
        {
            $this->addEntity($temp[1],"VARIABLE",$temp[0],0);
            return oseFirewallBase::prepareSuccessMessage("$entity has been whiteListed");
        }else{
            return oseFirewallBase::prepareErrorMessage("There was some problem in whitelisting $entity");
        }

    }

    public function checkDefaultWhiteListVariablesV7()
    {
        $defaultwhitelist_variable = array("POST.json", "POST.jform");  //needs to be in lower case because getwhitelist is in lowercase
        oseFirewall::callLibClass('fwscannerv7','whitelistmgmt');
        $whitelistvars = $this->getWhiteListEntitiesfromDB();
        if(isset($whitelistvars['status']) && $whitelistvars['status']=="ERROR")
        {
            return true;
        }else{
            if(empty($whitelistvars))
            {
                return true;
            }
            foreach($whitelistvars as $whitelistvar)
            {
                $formattedVar = $whitelistvar['request_type'].".".$whitelistvar['entity'];
                if(in_array($formattedVar,$defaultwhitelist_variable))
                {
                    $defaultwhitelist_variable =  array_diff($defaultwhitelist_variable,array($formattedVar));
                }
            }
            if(empty($defaultwhitelist_variable))
            {
                return false;
            }else{
                return true;
            }
        }

    }


    public function defaultWhiteListVariablesV7()
    {
        $defaultwhitelist_variable = array("POST.json", "POST.jform");
        $whitelistvars = $this->getWhiteListEntitiesfromDB();
        if(isset($whitelistvars['status']) && $whitelistvars['status']=="ERROR")
        {
            foreach($defaultwhitelist_variable as $var)
            {
                $temp1= $this->addWhiteListEntity($var);
                if($temp1['status']==0)
                {
                    return $temp1;
                }
            }
            return oseFirewallBase::prepareSuccessMessage("Default white list variables has been successfully added");
        }else{
            if(empty($whitelistvars))
            {
                foreach($defaultwhitelist_variable as $var)
                {
                    $temp1= $this->addWhiteListEntity($var);
                    if($temp1['status']==0)
                    {
                        return $temp1;
                    }
                }
                return oseFirewallBase::prepareSuccessMessage("Default white list variables has been successfully added");
            }
            foreach($whitelistvars as $whitelistvar)
            {
                $formattedVar = $whitelistvar['request_type'].".".$whitelistvar['entity'];
                if(in_array($formattedVar,$defaultwhitelist_variable))
                {
                    $defaultwhitelist_variable=  array_diff($defaultwhitelist_variable,array($formattedVar));
                }
            }
            if(empty($defaultwhitelist_variable))
            {
                return oseFirewallBase::prepareSuccessMessage("White list variables are Upto date");
            }else{
                foreach($defaultwhitelist_variable as $var)
                {
                    $temp1= $this->addWhiteListEntity($var);
                    if($temp1['status']==0)
                    {
                        return $temp1;
                    }
                }
                return oseFirewallBase::prepareSuccessMessage("Default white list variables has been successfully added");
            }
        }

    }
}