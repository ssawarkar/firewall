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
require_once('BaseModel.php');
class bsconfigv7Model extends BaseModel {
    public function __construct() {
        $this->loadLibrary ();
        $this->loadDatabase ();
    }
    protected function loadLibrary () {
        $this->loadFirewallStat () ;
        oseFirewallBase::callLibClass('fwscannerv7','fwscannerv7');
        $this->qatest = oRequest :: getInt('qatest', false);
        $this->fwscannerv7 = new oseFirewallScannerV7($this->qatest);
    }
    protected function loadDatabase () {
        $this->db = oseFirewall::getDBO();
    }
    public function loadLocalScript() {
        $this->loadAllAssets ();
        oseFirewall::loadJSFile ('CentroraSEOTinyMCE', 'plugins/tinymce/tinymce.min.js', false);
        oseFirewall::loadJSFile ('Bsconfigv7', 'bsconfigv7.js', false);
        oseFirewall::loadJSFile ('Slider', 'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-slider/7.1.0/bootstrap-slider.min.js', true);
    }

    public function saveSettings($array,$type)
    {
        $result = $this->fwscannerv7->saveSettings($array,$type);
        return $result;
    }

    public function getFirewallSettings()
    {
        $result = $this->fwscannerv7->getFirewallSettingsfromDb();
        return $result;
    }
    public function getIpInfo()
    {
        $result = $this->fwscannerv7->getIpInfo();
        return $result;
    }
    public function blacklistIp($ip)
    {
        $result = $this->fwscannerv7->addBlockedIp($ip);
        return $result;
    }

    public function saveSEOConfiguration($data,$type)
    {
        $result = $this->fwscannerv7->saveSettings($data,$type);
        return $result;
    }

    public function getSeoConfiguration()
    {
        $result = $this->fwscannerv7->getSeoConfiguration();
        return $result;
    }

    public function getLoginQRCode()
    {
        $result = $this->fwscannerv7->getLoginQRCode();
        return $result;
    }

    public function v6variablesexists()
    {
        oseFirewall::callLibClass('fwscannerv7','whitelistmgmt');
        $whitelistmgmt = new whitelistmgmt();
        $result = $whitelistmgmt->getExistingVariables();
        return $result;
    }

    public function getExtType()
    {
        $return = '<option value="Text Files">Text Files</option><option value="Data Files">Data Files</option><option value="Audio Files">Audio Files</option><option value="Video Files">Video Files</option>' .
            '<option value="3D Image Files">3D Image Files</option><option value="Raster Image Files">Raster Image Files</option><option value="Vector Image Files">Vector Image Files</option><option value="Page Layout Files">Page Layout Files</option><option value="Spreadsheet Files">Spreadsheet Files</option>' .
            '<option value="Database Files">Database Files</option><option value="Executable Files">Executable Files</option><option value="Game Files">Game Files</option><option value="CAD Files">CAD Files</option><option value="GIS Files">GIS Files</option><option value="Web Files">Web Files</option>' .
            '<option value="Plugin Files">Plugin Files</option><option value="Font Files">Font Files</option><option value="System Files">System Files</option><option value="Settings Files">Settings Files</option><option value="Encoded Files">Encoded Files</option><option value="Compressed Files">Compressed Files</option>' .
            '<option value="Disk Image Files">Disk Image Files</option><option value="Developer Files">Developer Files</option><option value="Backup Files">Backup Files</option><option value="Misc Files">Misc Files</option>';
        return $return;
    }

    public function toggleLoginGoogleAuthentication($value)
    {
        $result = $this->fwscannerv7->toggleLoginGoogleAuthentication($value);
        return $result;
    }

    public function toggleFirewallScanners($value)
    {
        $result = $this->fwscannerv7->toggleFirewallScanner($value);
        return $result;
    }
    public function getFirewallScannerVersion()
    {
        $result = $this->fwscannerv7->getFirewallScannerVersion();
        return $result;
    }

    public function getFolderPermissions()
    {
        $result = $this->fwscannerv7->checkPermissions();
        return $result;
    }
    public function isV7Activated()
    {
        $fw7_active   = oseFirewallBase::isFirewallV7Active();
        $active_rules = oseFirewallBase::anyActiveRules();
        return ($fw7_active && $active_rules);
    }

    public function isSuite()
    {
        $suite = oseFirewallBase::isSuite();
        if ($suite)
        {
            return oseFirewallBase::prepareSuccessMessage("Suite");
        }else{
            return oseFirewallBase::prepareErrorMessage("Plugin Version");
        }
    }

}

