<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 11/08/2016
 * Time: 11:51 AM
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
class Bsconfigv7statsModel extends BaseModel{
    public function __construct() {
        $this->loadLibrary ();
        $this->loadDatabase ();
    }
    protected function loadLibrary () {
        $this->loadFirewallStat () ;
        oseFirewallBase::callLibClass('fwscannerv7','fwstatsv7');
        $this->qatest = oRequest :: getInt('qatest', false);
        $this->fwscannerv7stats = new fwstatsv7();
    }
    protected function loadDatabase () {
        $this->db = oseFirewall::getDBO();
    }
    public function loadLocalScript() {
        $this->loadAllAssets ();
        oseFirewall::loadJSFile ('CentroraSEOTinyMCE', 'plugins/tinymce/tinymce.min.js', false);
        oseFirewall::loadJSFile ('FirewallStatsV7', 'fwstatsv7.js', false);
    }
    public function getBrowserStats()
    {
        $result =$this->fwscannerv7stats->getAttackStatistics();
        return $result;
    }
    public function getStats()
    {
        $result =$this->fwscannerv7stats->getAttackStatistics();
        return $result;
    }
    public function getDailyStats($month,$date)
    {
        $result =$this->fwscannerv7stats->getAnalysisofDay($month,$date);
        return $result;
    }
    public function housekeepingV7()
    {
        $result =$this->fwscannerv7stats->housekeepingV7();
        return $result;
    }
}