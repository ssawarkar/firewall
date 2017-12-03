<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 6/07/2016
 * Time: 11:59 AM
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
if(!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
require('BaseModel.php');
class IpManagementModel extends BaseModel{
//    public $ipmanagement = null;
    public $oseFirewallStat = null;
    public function __construct() {
        $this->loadLibrary ();
        $this->loadDatabase ();
    }
    protected function loadLibrary () {
        $this->loadFirewallStat () ;
        oseFirewall::callLibClass('fwscannerv7','ipManagement');
        $this->qatest = oRequest :: getInt('qatest', false);
        $this->ipmanagement = new ipManagement($this->qatest);
        $this->oseFirewallStat = new oseFirewallStat();
    }
    protected function loadDatabase () {
        $this->db = oseFirewall::getDBO();
    }
    public function loadLocalScript() {
        $this->loadAllAssets ();
        oseFirewall::loadJSFile ('CentroraSEOTinyMCE', 'plugins/tinymce/tinymce.min.js', false);
        oseFirewall::loadJSFile ('IpManagement', 'ipmanagement.js', false);
        oseFirewall::loadJSFile ('Slider', 'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-slider/7.1.0/bootstrap-slider.min.js', true);
    }
    public function getIpInfo()
    {
        $result = $this->ipmanagement->getIpInfo();
        return $result;
    }
    public function blacklistIp($idlist)
    {
        $result = $this->ipmanagement->changeStatusofIp($idlist,'2');
        return $result;
    }
    public function whitelistIp($idlist)
    {
        $result = $this->ipmanagement->changeStatusofIp($idlist,'1');
        return $result;
    }
    public function monitorIp($idlist)
    {
        $result = $this->ipmanagement->changeStatusofIp($idlist,'0');
        return $result;
    }
    public function addIp($ip,$status,$duration= false)
    {
        $result = $this->ipmanagement->addanIp($ip,$status,$duration);
        return $result;
    }
    public function clearAll()
    {
        $result = $this->ipmanagement->clearIPTable();
        return $result;
    }
    public function deleteItem($array)
    {
        $result =  $this->ipmanagement->deleteIps($array);
        return $result;
    }
    public function importcsv ($file)
    {
        $result =  $this->ipmanagement->importCSV($file);
        return $result;
    }

    public function exportCSV()
    {
        $result =  $this->ipmanagement->getExportButton();
        return $result;
    }
    public function downloadCSV($filename)
    {

        $this->ipmanagement->downloadcvs_fws7($filename);
    }
    public function viewAttackInfo($ip)
    {
        $result = $this->ipmanagement->viewAttackInfo($ip);
        return $result;
    }

    public function importips()
    {

        $result = $this->ipmanagement->importipsfromv6();
        return $result;
    }
    public function addEntityFromAttackLog($entity)
    {
        oseFirewall::callLibClass('fwscannerv7','whitelistmgmt');
        $whitelistgmt = new whitelistmgmt();
        $result =  $whitelistgmt->addWhiteListEntity($entity);
        return $result;
    }
    public function getTempWhiteListedIps()
    {

        $result = $this->ipmanagement->getTempWhiteListedIpsList();
        return $result;
    }
    public function deleteTempWhiteListIps($ip)
    {

        $result = $this->ipmanagement->deleteTempWhiteListIps($ip);
        return $result;
    }

}
