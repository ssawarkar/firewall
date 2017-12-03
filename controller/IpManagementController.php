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
namespace App\Controller;
if (!defined('OSE_FRAMEWORK') && !defined('OSEFWDIR') && !defined('_JEXEC'))
{
    die('Direct Access Not Allowed');
}
class IpManagementController extends \App\Base
{

    public function action_getIpInfo()
    {
        $this->model->loadRequest();
        $result = $this->model->getIpInfo();
        $this->model->returnJSON($result);
    }

    public function action_blacklistIp()
    {
        $this->model->loadRequest();
        $idlist = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($idlist);
        $result = $this->model->blacklistIp($idarray);
        $this->model->returnJSON($result);
    }

    public function action_whitelistIp()
    {
        $this->model->loadRequest();
        $idlist = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($idlist);
        $result = $this->model->whitelistIp($idarray);
        $this->model->returnJSON($result);
    }

    public function action_monitorIp()
    {
        $this->model->loadRequest();
        $idlist = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($idlist);
        $result = $this->model->monitorIp($idarray);
        $this->model->returnJSON($result);
    }

    public function action_addIp()
    {
        $this->model->loadRequest();
        $ip = $this->model->getVar('ip_start', null);
        $status = $this->model->getVar('ip_status', null);
        $duration = $this->model->getVar('duration',null);
        $result = $this->model->addIp($ip, $status,$duration);
        $this->model->returnJSON($result);
    }

    public function action_clearAll()
    {
        $this->model->loadRequest();
        $result = $this->model->clearAll();
        $this->model->returnJSON($result);
    }

    public function action_deleteItem()
    {
        $this->model->loadRequest();
        $idlist = $this->model->getVar('ids', null);
        $idarray = $this->model->JSON_decode($idlist);
        $result = $this->model->deleteItem($idarray);
        $this->model->returnJSON($result);
    }

//    public function action_importCVS()
//    {
//        $this->model->loadRequest();
//        $result = $this->model->importCSV();
//        $this->model->returnJSON($result);
//    }

    public function action_downloadCSV()
    {
        $this->model->loadRequest();
        $filename = $this->model->getVar('filename', null);
        $this->model->downloadCSV($filename);
    }

    public function action_importcsv()
    {
        $this->model->loadRequest();
        $result = $this->model->importcsv($_FILES);
        $this->model->returnJSON($result);
    }
    public function action_viewAttackInfo()
    {
        $this->model->loadRequest();
        $ip = $this->model->getVar('ip',null);
        $result = $this->model->viewAttackInfo($ip);
        $this->model->returnJSON($result);
    }

    public function action_importips()
    {
        $this->model->loadRequest();
        $result = $this->model->importips();
        $this->model->returnJSON($result);
    }

    public function action_addEntityFromAttackLog()
    {
        $this->model->loadRequest();
        $entity = $this->model->getVar('entity', null);
        $result = $this->model->addEntityFromAttackLog($entity);
        $this->model->returnJSON($result);
    }

    public function action_getTempWhiteListedIps()
    {
        $this->model->loadRequest();
        $result = $this->model->getTempWhiteListedIps();
        $this->model->returnJSON($result);
    }
    public function action_deleteTempWhiteListIps()
    {
        $this->model->loadRequest();
        $ip = $this->model->getVar('ip', null);
        $result = $this->model->deleteTempWhiteListIps($ip);
        $this->model->returnJSON($result);
    }
}

