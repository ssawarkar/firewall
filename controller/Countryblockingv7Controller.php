<?php
/**
 * Created by PhpStorm.
 * User: suraj
 * Date: 21/07/2016
 * Time: 1:52 PM
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
namespace App\Controller;
if (!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
class Countryblockingv7Controller extends \App\Base{
    public function action_GetCountryList() {
        $this->model->loadRequest ();
        if (isset($_REQUEST['mobiledevice']))
        {
            $mobiledevice = $this->model->getInt('mobiledevice', 0);
        }
        else
        {
            $mobiledevice = 0;
        }
        $results = $this ->model->getCountryList();
        $this->model->returnJSON($results, $mobiledevice);
    }
    public function action_ChangeCountryStatus()
    {
        $this->model->loadRequest();
        $id= $this->model->getInt('id', null);
        $status= $this->model->getInt('status', null);
        if (empty($id) || (!in_array($status, array(1,2,3))))
        {
            $this->model->showSelectionRequired ();
        }
        $result = $this->model->ChangeCountryStatus(array($id), $status);
        if ($result==true)
        {
            $this->model->aJaxReturn(true, 'SUCCESS', $this->model->getLang("COUNTRY_CHANGED_SUCCESS"), true);
        }
        else
        {
            $this->model->aJaxReturn(true, 'ERROR', $this->model->getLang("COUNTRY_CHANGED_FAILED"), false);
        }
    }
    public function action_BlacklistCountry()
    {
        $this->changeCountryStatus(1);
    }
    public function action_WhitelistCountry()
    {
        $this->changeCountryStatus(3);
    }
    public function action_MonitorCountry()
    {
        $this->changeCountryStatus(2);
    }
    private function changeCountryStatus($status)
    {
        $this->model->loadRequest();
        $aclids = $this->model->getVar('ids', null);
        $aclids = $this->model->JSON_decode($aclids);
        if (empty($aclids))
        {
            $this->model->showSelectionRequired ();
        }
        $result = $this ->model -> changeCountryStatus($aclids, $status);
        if ($result==true)
        {
            $this->model->aJaxReturn(true, 'SUCCESS', $this->model->getLang("COUNTRY_STATUS_CHANGED_SUCCESS"), false);
        }
        else
        {
            $this->model->aJaxReturn(false, 'ERROR', $this->model->getLang("COUNTRY_STATUS_CHANGED_FAILED"), false);
        }
    }
    public function action_deleteAllCountry()
    {
        $result = $this->model->deleteAllCountry();
        if ($result==true)
        {
            $this->model->aJaxReturn(true, 'SUCCESS', $this->model->getLang("COUNTRY_DATA_DELETE_SUCCESS"), false);
        }
        else
        {
            $this->model->aJaxReturn(false, 'ERROR', $this->model->getLang("COUNTRY_DATA_DELETE_FAILED"), false);
        }
    }
    public function action_DownLoadTables(){
        $this->model->loadRequest ();
        $step= $this->model->getInt('step');
        $results = $this ->model->downloadTables($step);
        $this->model->returnJSON($results);
    }
    public function action_CreateTables() {
        $this ->model->createTables();
    }
    public function actionChangeAllCountry() {
        $this->model->loadRequest ();
        $mobiledevice = 0 ;
        $countryStatus= oRequest::getInt('countryStatus', 2);
        $result = $this ->model->changeAllCountry($countryStatus);
        if ($result==true)
        {
            $this->model->aJaxReturn(true, 'SUCCESS', oLang::_get("The country status is updated successfully."), false);
        }
        else
        {
            $this->model->aJaxReturn(false, 'ERROR', oLang::_get("Failed updating the country status."), false);
        }
    }
}