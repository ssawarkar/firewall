<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 21/07/2016
 * Time: 1:55 PM
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
require_once('BaseModel.php');
class Countryblockingv7Model extends BaseModel{
    public function __construct()
    {
        $this->loadLibrary();
        $this->loadDatabase();
        oseFirewall::callLibClass("CountryBlock", "CountryBlock");
    }

    public function getCHeader()
    {
        if (oseFirewall::checkSubscriptionStatus(false) == false) {
            return '<div class="subscribe-header">' . oLang::_get('COUNTRYBLOCK_TITLE') . '</div>';
        } else {
            return oLang::_get('COUNTRYBLOCK_TITLE');
        }
    }

    public function getCDescription()
    {
        if (oseFirewall::checkSubscriptionStatus(false) == false) {
            return '<div class="subscribe-subheader">' . oLang::_get('COUNTRYBLOCK_DESC') . '</div>';
        } else {
            return oLang::_get('COUNTRYBLOCK_DESC');
        }
    }

    public function getBriefDescription()
    {
        return '<div class="subscribe-desc">' . oLang::_get('COUNTRYBLOCK_DESC_BRIEF') . '</div>';
    }

    public function showSubPic()
    {
        return OSE_FWPUBLICURL . "/images/premium/flags.png";
    }

    public function showSubDesc()
    {
        return oLang::_get('COUNTRYBLOCK_DESC_SLOGAN');
    }

    public function loadLocalScript()
    {
        $this->loadAllAssets();
        oseFirewall::loadJSFile('CentroraManageJQPieChart', 'plugins/pie-chart/jquery.easy-pie-chart.js', false);
        oseFirewall::loadJSFile('CentroraManageIPs', 'countryblockingv7.js', false);
    }

    public function getCountryList()
    {
        $return = array();
        $CountryBlock = new CountryBlock();
        if (oseFirewall::isGeoDBReady()) {
            $return = $CountryBlock->getCountryList();
        } else {
            $return = $this->getEmptyReturn();
        }
        $return['draw'] = $this->getInt('draw');
        return $return;
    }

    public function changeCountryStatus($aclids, $status)
    {
        $CountryBlock = new CountryBlock();
        foreach ($aclids as $aclid) {
            $result = $CountryBlock->changeCountryStatus($aclid, $status);
        }
        return $result;
    }

    public function deleteAllCountry()
    {
        $CountryBlock = new CountryBlock();
        $result = $CountryBlock->deleteAllCountry();
        return $result;
    }

    public function downloadTables($step)
    {
        $CountryBlock = new CountryBlock();
        $results = $CountryBlock->downloadDB($step);
        return $results;
    }

    public function createTables()
    {
        oseFirewall::loadInstaller();
        oseFirewall::loadRequest();
        $step = oRequest::getInt('step');
        $retMessage = $this->getRetMessage($step);
        switch ($step) {
            case 0:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 1:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 2:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 3:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 4:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 5:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 6:
                $result = $this->insertGeoIPData($step);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 7:
                $result = $this->createCountryDB();
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
//			case 8:
//			case 9:
//			case 10:
//			case 11:
//			case 12:
//			case 13:
            case 8:
                //$result = $this->installGeoIPDB($step -9);
                $result = $this->cleanGeoIPDB($step - 1);
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 9:
                $result = $this->createDetMalwareView();
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            case 10:
                $result = $this->cleanCountryDB();
                $step++;
                $this->throwAjaxRecursive($result, 'Success', $retMessage, true, $step);
                break;
            default:
                $this->throwAjaxReturn(true, 'Completed', $retMessage, false);
                break;
        }
    }

    private function getRetMessage($step)
    {
        $return = '';
        $array = array();
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE1_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE2_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE3_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE4_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE5_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE6_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE7_GEOIPDATA_COMPLETED'));
        $array[] = $this->transMessage(true, oLang::_get('INSERT_STAGE8_GEOIPDATA_COMPLETED'));
        $i = 0;
        while ($i <= $step) {
            if (isset($array[$i])) {
                $return .= $array[$i];
            }
            $i++;
        }
        return $return;
    }

    private function insertGeoIPData($step)
    {
        $installer = new oseFirewallInstaller();
        if (file_exists(OSE_FWDATA . ODS . 'osegeoip' . $step . '.sql')) {
            $installer->installGeoIPDB($step, OSE_FWDATA . ODS . 'osegeoip{num}.sql');
        } else {
            return false;
        }
    }

    private function createCountryDB()
    {
        $installer = new oseFirewallInstaller();
        $blocker = new CountryBlock();
        $dbFile = OSE_FWDATA . ODS . 'wp_osefirewall_country.sql';
        $result = $installer->createCountryDB($dbFile);
        $blocker->alterTable();
        return $result;
    }

    public function showStatus()
    {
        $dbReady = $this->isDBReady();
        $action = ' <a href="#" class="button-primary" onClick = "downLoadDB()">heal me</a>';
        if ($dbReady['ready'] == false) {
            echo '<div class ="warning"> ' . oLang::_get('GEONOTREADY') . '' . $action . '</div>';
        }
    }

    public function isDBReady()
    {
        $return = array();
        $return['ready'] = oseFirewall::isGeoDBReady();
        $return['type'] = 'base';
        return $return;
    }

    private function createDetMalwareView()
    {
        return true;
    }

    private function cleanGeoIPDB($step)
    {
        $installer = new oseFirewallInstaller();
        $result = $installer->cleanGeoIPDB($step);
        return $result;
    }

    private function cleanCountryDB()
    {
        $installer = new oseFirewallInstaller();
        $dbFile = OSE_FWDATA . ODS . 'wp_osefirewall_country.sql';
        $result = $installer->cleanCountryDB($dbFile);
        return $result;
    }

    public function getStatistics()
    {
        oseFirewall::callLibClass('CountryBlock', 'CountryBlock');
        $countryblock = new CountryBlock();
        return $countryblock->getCountryBlockStatistic();
    }

    public function changeAllCountry($countryStatus = 2)
    {
        oseFirewall::callLibClass('CountryBlock', 'CountryBlock');
        $countryblock = new CountryBlock();
        return $countryblock->changeAllCountry($countryStatus);
    }
}