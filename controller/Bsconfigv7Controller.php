<?php
namespace App\Controller;
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
class Bsconfigv7Controller extends \App\Base {


    public function action_saveSettings()
    {
        $this->model->loadRequest();
        $array = $this->model->getVar('settings',null);
        $result = $this->model->saveSettings($array,'general');
        $this->model->returnJSON($result);
    }

    public function action_getFirewallSettings()
    {
        $this->model->loadRequest();
        $result = $this->model->getFirewallSettings();
        $this->model->returnJSON($result);
    }

    public function action_saveConfigSEO ()
    {
        $this->model->loadRequest ();
        $type = $this->model->getVar('type', null);
        if (empty($type))
        {
           $result['status'] = 0;
           $result['info'] = 'Type variable is not set';
           return  $this->model->returnJSON($result);
        }
        if($type == 'seo_wizard')
        {
            $data = $this->model->getVar('data',null);
        }else {
            $data = array();
            $data['18'] = $this->model->getVar('pageTitle', null);
            $data['19'] = $this->model->getVar('metaKeywords', null);
            $data['20'] = $this->model->getVar('metaDescription', null);
            $data['21'] = $this->model->getVar('metaGenerator', null);
            $data['22'] = $this->model->getInt('scanGoogleBots', 0);
            $data['23'] = $this->model->getInt('scanYahooBots', 0);
            $data['24'] = $this->model->getInt('scanMsnBots', 0);
        }

        $result = $this->model->saveSEOConfiguration($data,'seo');
        $this->model->returnJSON($result);
    }
    public function action_getSEOConfiguration()
    {
        $this->model->loadRequest();
        $result = $this->model->getSeoConfiguration();
        $this->model->returnJSON($result);
    }

    public function action_getLoginQRCode()
    {
        $this->model->loadRequest();
        $result = $this->model->getLoginQRCode();
        $this->model->returnJSON($result);
    }

    public function action_v6variablesexists()
    {
        $this->model->loadRequest();
        $result = $this->model->v6variablesexists();
        $this->model->returnJSON($result);
    }
    public function action_toggleLoginGoogleAuthentication()
    {
        $this->model->loadRequest();
        $value = $this->model->getVar('loginGAuth',null);
        $result = $this->model->toggleLoginGoogleAuthentication($value);
        $this->model->returnJSON($result);
    }
    public function action_toggleFirewallScanners()
    {
        $this->model->loadRequest();
        $value = $this->model->getVar('value',null);
        $result = $this->model->toggleFirewallScanners($value);
        $this->model->returnJSON($result);
    }
    public function action_getFirewallScannerVersion()
    {
        $this->model->loadRequest();
        $result = $this->model->getFirewallScannerVersion();
        $this->model->returnJSON($result);
    }
    public function action_getFolderPermissions()
    {
        $this->model->loadRequest();
        $result = $this->model->getFolderPermissions();
        $this->model->returnJSON($result);
    }

    public function action_isV7Activated()
    {
        $this->model->loadRequest();
        $result = $this->model->isV7Activated();
        $this->model->returnJSON($result);
    }

    public function action_isSuite()
    {
        $this->model->loadRequest();
        $result = $this->model->isSuite();
        $this->model->returnJSON($result);
    }


}