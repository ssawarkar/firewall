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
class CountryBlock
{
	protected $db = null;
	protected $where = array();
	protected $orderBy = ' ';
	protected $limitStm = ' ';
	public function __construct()
	{
		$this->setDBO ();
	}
	protected function setDBO () {
		$this->db = oseFirewall::getDBO();
	}
	public function downloadDB($step)
	{
		$step = $step - 2;
		if ($step == - 1)
		{
			$handle = $this->downloadFile("https://www.centrora.com/downloads/geoip/wp_osefirewall_country".".data");
			if ($handle == false)
			{
				oseAjax::aJaxReturn(false, 'ERROR', DB_COUNTRYBLOCK_FAILED_INCORRECT_PERMISSIONS, $continue = false, $id = null);
			}
			else
			{
				$return["result"] = "osefirewall_country.sql downloaded.";
				$return["status"] = "unfinish";
			}
		}
		else
			if ($step < -1)
			{
				$return["result"] = "Downloading complete.";
				$return["status"] = "Completed";
			}
			else
			{
				if (file_exists(OSE_FWDATA.ODS."osegeoip".$step.".sql"))
				{
					$return["result"] = "osegeoip".$step.".sql downloaded.";
					$return["status"] = "unfinish";
				}
				else
				{
					$handle = $this->downloadFile("https://www.centrora.com/downloads/geoip/osegeoip".$step.".data");
					if ($handle == false)
					{
						oseAjax::aJaxReturn(false, 'ERROR', DB_COUNTRYBLOCK_FAILED_INCORRECT_PERMISSIONS, $continue = false, $id = null);
					}
					else
					{
						$return["result"] = "osegeoip".$step.".sql downloaded.";
						$return["status"] = "unfinish";
					}
				}
			}
		return $return;
	}
	private function downloadFile($url, $target = false)
	{
		$url_fopen = ini_get('allow_url_fopen');
		if ($url_fopen == true)
		{
			$handle = $this->downloadThroughFopen($url, $target);
		    if($handle== false)
            {
                $handle = $this->downloadThroughCURL ($url, $target);
            }
        }
		else
		{
			$handle = $this->downloadThroughCURL ($url, $target); 
		}
		return $handle;  
	}
	private function downloadThroughCURL ($url, $target = false) {
		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		$contents = curl_exec($curl);
		curl_close($curl);
		$tmp = basename($url, ".data");
		$target = OSE_FWDATA.ODS.$tmp.".sql";
		$handle = is_int(file_put_contents($target, $contents)) ? true : false;
		return $handle;
	}
	private function downloadThroughFopen ($url, $target = false) {
		$inputHandle = fopen($url, "r");
		// Set the target path to store data
		$tmp = basename($url, ".data");
		$target = OSE_FWDATA.ODS.$tmp.".sql";
		if (!$inputHandle)
		{
			return false;
		}
		$meta_data = stream_get_meta_data($inputHandle);
		// Initialise contents buffer
        if(!empty($meta_data) && isset($meta_data['wrapper_data']) && isset($meta_data['wrapper_data']['headers']) && empty($meta_data['wrapper_data']['headers']))
        {
            return false;
        }
		$contents = null;
		while (!feof($inputHandle))
		{
			$contents .= fread($inputHandle, 8192);
			if ($contents === false)
			{
				return false;
			}
		}
		// Write buffer to file
		$handle = is_int(file_put_contents($target, $contents)) ? true : false;
		if ($handle)
		{
			// Close file pointer resource
			fclose($inputHandle);
		}
		return $handle;		
	}
	public function getCountryList()
	{
		$columns = oRequest::getVar('columns', null);
		$limit = oRequest::getInt('length', 15);
		$start = oRequest::getInt('start', 0);
		$search = oRequest::getVar('search', null);
		$orderArr = oRequest::getVar('order', null);
		$sortby = null;
		$orderDir = 'asc';
		if (!empty($columns[3]['search']['value']))
		{
			$status = $columns[3]['search']['value'];
		}
		else
		{
			$status = null;
		}
		if (!empty($orderArr[0]['column']))
		{
			$sortby = $columns[$orderArr[0]['column']]['data'];
			$orderDir = $orderArr[0]['dir'];
		}
		$return = $this->getCountryDB($search['value'], $status, $start, $limit, $sortby, $orderDir);
		$return['data'] = $this->convertCountryIPMap($return['data']);
		return $return;
	}
	protected function getWhereName ($search) {
		$this->where[] = "`country_name` LIKE ".$this->db->quoteValue('%'.$search.'%', true)." OR `country_code` LIKE ".$this->db->quoteValue('%'.$search.'%', true);
	}
	protected function getWhereStatus ($status) {
		if ($status == '1' || $status == '3')
		{
			$this->where[] = "`status` = ".(int) $status;
		}
		else if ($status == '2')
		{
			$this->where[] = "`status` = ".(int) $status. " OR `status` = 0 ";
		}
	}
	protected function getOrderBy ($sortby, $orderDir) {
		$this->orderBy= " ORDER BY ".addslashes($sortby).' '.addslashes($orderDir);
	}
	protected function getLimitStm ($start, $limit) {
		if (!empty($limit))
		{
			$this->limitStm = " LIMIT ".(int)$start.", ".(int)$limit;
		}
	}
	private function getCountryDB($search, $status, $start, $limit, $sortby, $orderDir)
	{
		$return = array ();
		if (!empty($search)) {$this->getWhereName ($search);}
		if (!empty($status)) {$this->getWhereStatus ($status);}
		if (!empty($sortby)) {$this->getOrderBy ($sortby, $orderDir);}
		if (!empty($limit)) {$this->getLimitStm ($start, $limit);}
		$where = $this->db->implodeWhere($this->where);
		// Get Records Query;
		$return['data'] = $this->getAllRecords ($where);
		$counts = $this->getAllCounts($where);
		$return['recordsTotal'] = $counts['recordsTotal'];
		$return['recordsFiltered'] = $counts['recordsFiltered'];
		return $return;
	}
	private function getAllRecords ($where) {
		$sql = "SELECT	`country`.`country_id` AS `id`, `country`.`country_name`AS `name`, `country`.`country_code`,`country`.`status` AS `status`
				FROM (`#__osefirewall_country` AS `country`) ";
		$query = $sql.$where.$this->orderBy." ".$this->limitStm;
		$this->db->setQuery($query);
		$results = $this->db->loadObjectList();
		return $results;
	}
	private function getAllCounts($where) {
		$return = array();
		// Get total count
		$sql = "SELECT	COUNT(`country`.`country_id`) AS `count` FROM (`#__osefirewall_country` AS `country`) ";
		$this->db->setQuery($sql);
		$result = $this->db->loadObject();
		$return['recordsTotal'] = $result->count;
		// Get filter count
		$this->db->setQuery($sql.$where);
		$result = $this->db->loadObject();
		$return['recordsFiltered'] = $result->count;
		return $return;
	}
	private function convertCountryIPMap($results)
	{
		$i = 0;
		foreach ($results as $result)
		{
			if (!isset($results[$i]->country_code) || empty($results[$i]->country_code))
			{
				//TODO: convert country code!
				//$results[$i]->country_code = $this->updateCountryCode($results[$i]->id, $results[$i]->ip32_start);
			}
			$results[$i]->country_code = $this->getCountryImage($results[$i]->country_code);
			if (empty($results[$i]->host))
			{
				//$results[$i]->host = $this->updateIPHost($results[$i]->id, $results[$i]->ip32_start);
			}
			$results[$i]->status = $this->getStatusIcon($results[$i]->id, $results[$i]->status);
			$results[$i]->checkbox = '';
			$i++;
		}
		return $results;
	}
	private function getViewIcon($id)
	{
		return "<a href='#' onClick= 'viewIPdetail(".urlencode($id).")' ><div class='ose-grid-info'></div></a>";
	}
	private function getStatusIcon($id, $status)
	{
		switch ($status)
		{
		case '3':
			return "<a href='#' title = 'Active' onClick= 'changeItemStatus(".urlencode($id).", 2)' ><div class='grid-accept'></div></a>";
			break;
		default:
		case '2':
			return "<a href='#' title = 'Monitored' onClick= 'changeItemStatus(".urlencode($id).", 1)' ><div class='grid-error'></div></a>";
			break;
		case '1':
			return "<a href='#' title = 'Inactive' onClick= 'changeItemStatus(".urlencode($id).", 3)' ><div class='grid-block'></div></a>";
			break;
		}
	}
	private function getCountryImage($country_code)
	{
		if (empty($country_code))
		{
			return '';
		}
		else
		{
			if (file_exists(OSEAPPDIR."/public/images/flags/".strtolower($country_code).".png"))
			{
				return "<img src='".OSE_FWPUBLICURL."/images/flags/".strtolower($country_code).".png' alt='".$country_code."' />";
			}
			else 
			{
				return strtolower($country_code);
			}
		}
	}

	public function getCountryFlagForEMail($code)
	{
		$result = $this->getCountryImage($code);
		return $result;
	}

	public function getCountryName($code)
	{
		$sql = "SELECT	`country_name` FROM `#__osefirewall_country` WHERE `country_code` = ".$this->db->quoteValue($code);
		$this->db->setQuery($sql);
		$result = $this->db->loadObject();
		return $result;
	}
	public function deleteAllCountry () {
		$result = true;
		$result = $this->db->dropTable('#__osefirewall_country');
		$result = $this->db->truncateTable('#__ose_app_geoip');
		return $result;
	}
	

	
	public function changeCountryStatus($country_id, $status)
	{
		$db = oseFirewall::getDBO();
		$varValues = array(
			'status' => (int) $status
		);
		$result = $db->addData('update', '#__osefirewall_country', 'country_id', (int) $country_id, $varValues);
		$db->closeDBO ();
		return $result;
	}
	public function alterTable()
	{
		if ($this->checkTableAltered() == true)
		{
			$this->alterGeoIPTable();
			$this->alterCountryTable();
		}
	}
	private function alterGeoIPTable()
	{
		$result = $this->checkGeoIPIndextExists();
		if (!$result)
		{
			$db = oseFirewall::getDBO();
			$query = "CREATE INDEX `index_ip32_start` ON `#__ose_app_geoip` (`ip32_start`(10))";
			$db->setQuery($query);
			$results = $db->query();
			$query = "CREATE INDEX `index_ip32_end` ON `#__ose_app_geoip` (`ip32_end`(10))";
			$db->setQuery($query);
			$results = $db->query();
			$db->closeDBO ();
		}
	}
	private function checkTableAltered()
	{
		$db = oseFirewall::getDBO();
		$query = "SHOW COLUMNS FROM `#__osefirewall_country` LIKE 'country_3_code'";
		$db->setQuery($query);
		$results = $db->loadObjectList();
		$db->closeDBO ();
		if (!empty($results) && $results[0] != null)
		{
			return true;
		}
		return false;
	}
	private function checkGeoIPIndextExists()
	{
		$db = oseFirewall::getDBO();
		$query = "SELECT COUNT( * ) AS index_exists
				  FROM information_schema.statistics
				  WHERE table_name = '#__ose_app_geoip'
				  AND index_name = 'index_ip32_start'";
		$db->setQuery($query);
		$results = $db->loadObjectList();
		if ($results[0]->index_exists > 0)
		{
			$db->closeDBO ();
			return true;
		}
		$query = "SELECT COUNT( * ) AS index_exists
				  FROM information_schema.statistics
				  WHERE table_name = '#__ose_app_geoip'
				  AND index_name = 'index_ip32_end'";
		$db->setQuery($query);
		$results = $db->loadObjectList();
		if ($results[0]->index_exists > 0)
		{
			$db->closeDBO ();
			return true;
		}
		$db->closeDBO ();
		return false;
	}
	private function alterCountryTable()
	{
		$db = oseFirewall::getDBO();
		$query = "ALTER TABLE `#__osefirewall_country` DROP COLUMN `country_3_code`";
		$db->setQuery($query);
		$results = $db->query();
		$query = "ALTER TABLE `#__osefirewall_country` CHANGE `country_2_code` `country_code` char(2)";
		$db->setQuery($query);
		$results = $db->query();
		$query = "ALTER TABLE `#__osefirewall_country` ADD COLUMN `status` Tinyint DEFAULT 2";
		$db->setQuery($query);
		$results = $db->query();
		$db->closeDBO ();
	}
	public function getCountryBlockStatistic()
	{
		$db = oseFirewall::getDBO();
		$data = $db->isTableExists('#__osefirewall_country');
		if (empty($data))
		{
			return false;
		}
		$query = "SELECT status, count(status) as number FROM `#__osefirewall_country` group by status;";
		$db->setQuery($query);
		$results = $db->loadObjectList();
		$db->closeDBO ();
		return $this->convertStatistic($results);
	}
	private function convertStatistic($results)
	{
		$i = 0;
		$return = array();
		foreach ($results as $result)
		{
			if (isset($results[$i]->status) && !empty($results[$i]->status))
			{
				switch ($results[$i]->status)
				{
				case 1:
					$return['blacklisted'] = $results[$i]->number;
					break;
				case 3:
					$return['whitelisted'] = $results[$i]->number;
					break;
				}
			}
			$i++;
		}
		return $return;
	}
	public function changeAllCountry ($countryStatus) {
		$db = oseFirewall::getDBO();
		$query = "UPDATE `#__osefirewall_country` SET `status` = ". (int)$countryStatus;
		$db->setQuery($query);
		$result = $db->query();
		$db->closeDBO ();
		return $result;		
	}

	public function getCountryCode($ip32long)
	{
		$db = oseFirewall::getDBO();
		$query = "SELECT * FROM `#__ose_app_geoip` WHERE ".$ip32long." BETWEEN `ip32_start` AND `ip32_end`";
		$db->setQuery($query);
		$results = $db->loadArrayList();
		$db->closeDBO ();
		if(!empty($results))
		{
			return $results[0]['country_code'];
		}else {
			return false;
		}
	}
}
?>